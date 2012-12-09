s2e = {
  kleeArgs = {
		--"--use-dfs-search=true",
		"--use-batching-search=true", "--batch-time=1.0",
  }
}

plugins = {
	--"FunctionMonitor",
	"WindowsMonitor",
	"ModuleExecutionDetector",
	"ExecutionTracer",
	--"TestCaseGenerator",
	--"LibraryCallMonitor",
	--"ModuleTracer",
	--"OSMonitor",
	--"ExampleX86Exception",
	--"SocketTracker",
	--"LibraryCallMonitor",
	--"MemoryChecker",
	--"MemoryTracer",
	"AssertExpert",
	--"VulMining",
	"StackMonitor",
	"StackChecker",
	--"BaseInstructions",
	-- Track when the guest loads programs
  	--"RawMonitor",
	-- Restrict symbolic execution to
  	-- the programs of interest
  	--"CodeSelector",
	"InstructionTracker",
}

pluginsConfig = {}

pluginsConfig.ExecutionTracer = {}

pluginsConfig.TestCaseGenerator = {}

pluginsConfig.ModuleTracer = {}

pluginsConfig.WindowsMonitor = {
    version="XPSP3",
    --version="XPSP2",
    userMode=true,
    kernelMode=true,
    --kernelMode=true,
    checked=false,
    --checked=true,
    monitorModuleLoad=true,
    monitorModuleUnload=true,
    monitorProcessUnload=true,
    --monitorThreads=false,
	modules = {
		--sock_id = {
			
			--name="server430.exe",
			--name="qqplayer.exe",
			--name="demo.exe",
			--name="pngview.exe",
			--name="notepad.exe",
			--name="server430.exe",
			--name="pngcheck.exe",
			--name="png2bmp.exe",
			--size=137728,
			--size=330000,
		--},
		sock_id3 = {
			--name="ws2_32.dll",
			name="fileop_noloop_size_over_re.exe",
		},
	},
}

pluginsConfig.ModuleExecutionDetector = {
    trackAllModules=false,
   -- configureAllModules=false,
--modules={
	--moduleName="server430.exe",
	--moduleName="ws2_32.dll",
	--userMode=true,
	--kernelMode=false,
--}
    --sock_id1 = {
	--moduleName="client430.exe",
	
        --moduleName = "qqplayer.exe",
        --moduleName = "demo.exe",
        --moduleName = "pngview.exe",
        --moduleName = "notepad.exe",
	--moduleName = "server430.exe",
        --moduleName = "pngcheck.exe",
        --moduleName = "png2bmp.exe",
        --kernelMode= false,
	--userMode=true,
    --},
    --sock_id2 ={
	--moduleName="ws2_32.dll",
	--kernelMode =false,
	--userMode=true,
	--},
    sock_id3 = {
	--moduleName="wsabuftest_debug_9999.exe",
	moduleName="fileop_noloop_size_over_re.exe",
        --moduleName = "qqplayer.exe",
        --moduleName = "demo.exe",
        --moduleName = "pngview.exe",
        --moduleName = "notepad.exe",
	--moduleName = "server430.exe",
        --moduleName = "pngcheck.exe",
        --moduleName = "png2bmp.exe",
        kernelMode= false,
	userMode=true,
    },
}
	
pluginsConfig.LibraryCallMonitor = {
    displayOnce=true,
    moduleIds = {"sock_id3"},
}
    
pluginsConfig.MemoryChecker = { 
      checkMemoryErrors = true, 
      checkMemoryLeaks  = true, 
      checkResourceLeaks = true, 
      terminateOnErrors  = false, 
      terminateOnLeaks   = false, 
      traceMemoryAccesses = false,
}
      
pluginsConfig.MemoryTracer = {}
