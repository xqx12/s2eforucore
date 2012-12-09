s2e = {
  kleeArgs = {
   "--use-batching-search=true", "--batch-time=2.0"
   -- "--use-iterative-deepening-time-search=true", "--batch-time=2.0"
   -- "--use-dfs-search"
  }
}
plugins = {
  -- Enable S2E custom opcodes
  "BaseInstructions",

  -- Basic tracing, required for test case generation
  -- "ExecutionTracer",

  --  "HostFiles"

  -- Enable the test case generator plugin
  -- "TestCaseGenerator"
}

--pluginsConfig.HostFiles = {
--    baseDir = "/home/s2e/s2e/demos"
--}
