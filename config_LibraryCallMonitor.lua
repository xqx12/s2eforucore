
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
  "LibraryCallMonitor",
  "FunctionMonitor"
}

pluginsConfig = {
}

pluginsConfig.RawMonitor={
  kernelStart=0xc0000000,
  main={
    name="main",
    start=0x0,
    size=8576,
    nativebase=0x08048000,
    delay=false,
    kernelmode=false
  },
  libmylib={
    name="libtiger.so",
    start=0x0,
    size=1234,
    nativebase=0x08048000,
    delay=false,
    kernelmode=false
  }
}

pluginsConfig.ModuleExecutionDetector={
  trackAllModules=1,
  main={
    moduleName="main",
    kernelMode=false
  },
  libmylib={
    moduleName="libtiger.so",
    kernelMode=false
  }
}

pluginsConfig.LibraryCallMonitor={
  displayOnce=true,
  moduleIds={
    "main",
    "libmylib",
 }
}
