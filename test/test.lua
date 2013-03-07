-- config.lua

s2e = {
   kleeArgs = {
--      "--use-batching-search=true", "--batch-time=1.0",
      "--use-dfs-search=true",
      "--print-mode-switch",
--      "--print-llvm-instructions",
   }
}

plugins = {
--     "BaseInstructions"
   "UCoreBaseInstructions",
   "UCoreMonitor",
   "ExecutionTracer",
--   "ModuleExecutionDetector",
   "RawMonitor",
--   "ConcolicDFSSearcher",
--   "UCoreMemoryManagement"
}

pluginsConfig = {
}

pluginsConfig.RawMonitor = {
    kernelStart = 0xc0000000,
    myprog_id = {
        delay = true,
        name = "tests2e",
        start = 0x0,
        size = 52505,
        nativebase = 0x8048000,
        kernelmode = false
    }
}


pluginsConfig.BaseInstructions = {
}

pluginsConfig.UCoreMonitor = {
   kernelBase  = 0xc0100000,
   kernelEnd = 0xc01000ff,
   MonitorFunction = true,
   system_map_file = "/home/xqx/xqx/git/s2eforucore/lab5_result/obj/kernel.sym"
}

pluginsConfig.UCoreMemoryManagement = {
   print_pgdir_pc = 0xc010008f
}
