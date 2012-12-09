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
   "ConcolicDFSSearcher",
--   "UCoreMemoryManagement"
}

pluginsConfig = {
}


pluginsConfig.BaseInstructions = {
}

pluginsConfig.UCoreMonitor = {
   kernelBase  = 0xc0100000,
   kernelEnd = 0xc01000ff,
   MonitorFunction = true,
   system_map_file = "/home/xqx/ucore/lab5/obj/kernel.sym"
}

pluginsConfig.UCoreMemoryManagement = {
   print_pgdir_pc = 0xc010008f
}
