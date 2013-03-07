-- File: config.lua
s2e = {
  kleeArgs = {
    -- Run each state for at least 1 second before
    -- switching to the other:
    "--use-batching-search=true", "--batch-time=1.0"
  }
}
plugins = {
  -- Enable a plugin that handles S2E custom opcode
  "BaseInstructions",
  "RawMonitor",
  "ModuleExecutionDetector",
  "FunctionMonitor",
  "Annotation"
}

pluginsConfig = {
}

pluginsConfig.RawMonitor = {
	kernelStart = 0xc0000000,
	mymodule = {
		delay = true,
		name = "user_main",
		start = 0,
		size = 100,
		nativebase = 0xc010be1d,
		kernelmode = true
	}
}

pluginsConfig.ModuleExecutionDetector = {
	mytest = {
		moduleName = "user_main",
		kernelMode = true,
	},
}

function annotation_example(state, plg)
	pkt = state:test();
end

pluginsConfig.Annotation = {
	init1 = {
		active=true,
		module="mytest",
		address=0xc010be1d,
		instructionAnnotation="annotation_example"
	}
}
