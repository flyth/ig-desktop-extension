package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/labstack/echo/middleware"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type IGWeb struct {
	runtime runtime.Runtime
}

type GadgetEvent struct {
	ID      string          `json:"id"`
	Type    uint32          `json:"type,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

var lrlogger = logrus.New()

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	var socketPath string
	flag.StringVar(&socketPath, "socket", "/run/guest-services/backend.sock", "Unix domain socket to listen on")
	flag.Parse()

	_ = os.RemoveAll(socketPath)

	lrlogger.SetOutput(os.Stdout)

	logMiddleware := middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: middleware.DefaultSkipper,
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}",` +
			`"method":"${method}","uri":"${uri}",` +
			`"status":${status},"error":"${error}"` +
			`}` + "\n",
		CustomTimeFormat: "2006-01-02 15:04:05.00000",
		Output:           lrlogger.Writer(),
	})

	lrlogger.Infof("Starting listening on %s\n", socketPath)
	router := echo.New()
	router.HideBanner = true
	router.Use(logMiddleware)
	startURL := ""

	ln, err := listen(socketPath)
	if err != nil {
		lrlogger.Fatal(err)
	}
	router.Listener = ln

	ig := &IGWeb{
		runtime: local.New(),
	}
	ig.runtime.Init(ig.runtime.ParamDescs().ToParams())
	err = operators.GetAll().Init(operators.GlobalParamsCollection())
	if err != nil {
		log.Printf("error initializing operators: %v", err)
	}
	router.POST("/gadget", ig.runGagdet)

	lrlogger.Fatal(router.Start(startURL))
}

func listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

type GadgetStartRequest struct {
	ID             string            `json:"id"`
	GadgetName     string            `json:"gadgetName"`
	GadgetCategory string            `json:"gadgetCategory"`
	Params         map[string]string `json:"params"`
	Timeout        int               `json:"timeout"`
	LogLevel       int               `json:"logLevel"`
}

func (ig *IGWeb) runGagdet(ctx echo.Context) error {
	var request GadgetStartRequest
	if err := ctx.Bind(&request); err != nil {
		return ctx.String(500, err.Error())
	}

	// Build a gadget context and wire everything up
	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Get per gadget operators
	ops := operators.GetOperatorsForGadget(gadgetDesc)
	ops.Init(operators.GlobalParamsCollection())

	operatorParams := ops.ParamCollection()
	err := operatorParams.CopyFromMap(request.Params, "operator.")
	if err != nil {
		return fmt.Errorf("setting operator parameters: %w", err)
	}

	logger := logger.DefaultLogger()

	parser := gadgetDesc.Parser()

	runtimeParams := ig.runtime.ParamDescs().ToParams()
	err = runtimeParams.CopyFromMap(request.Params, "runtime.")
	if err != nil {
		return fmt.Errorf("setting runtime parameters: %w", err)
	}

	gadgetParamDescs := gadgetDesc.ParamDescs()
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()

	err = gadgetParams.CopyFromMap(request.Params, "")
	if err != nil {
		return fmt.Errorf("setting gadget parameters: %w", err)
	}

	var output = make(map[string]any)
	events := make([]any, 0)

	if parser != nil {
		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			events = append(events, ev)
		})
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	if request.Timeout == 0 {
		request.Timeout = int(time.Second)
	}

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx.Request().Context(),
		runID,
		ig.runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
	)

	logger.Warnf("started gadget %s (%s/%s)", request.ID, request.GadgetCategory, request.GadgetName)

	defer gadgetCtx.Cancel()

	// Hand over to runtime
	results, err := ig.runtime.RunGadget(gadgetCtx)
	output["results"] = results
	if err != nil {
		output["err"] = err.Error()
	}
	output["events"] = events

	return ctx.JSON(http.StatusOK, output)
}

type HTTPMessageBody struct {
	Message string
}
