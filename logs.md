Traceback (most recent call last):
  File "/home/surzal/stuff/daharness/executor.py", line 307, in _launch_in_process
    result = await asyncio.to_thread(functools.partial(func, **args))
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/asyncio/threads.py", line 25, in to_thread
    return await loop.run_in_executor(None, func_call)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/concurrent/futures/thread.py", line 59, in run
    result = self.fn(*self.args, **self.kwargs)
  File "/home/surzal/stuff/utils/findings.py", line 73, in report_finding
    [s.strip() for s in tool_chain.split(",") if s.strip()] if tool_chain else []
                        ^^^^^^^^^^^^^^^^
AttributeError: 'list' object has no attribute 'split'
2026-09-08 21:52:40,940 [INFO] MCP executed tool utils.findings.report_finding for intent 'None' (session=0) with result: {'error': "In-process launch failed: 'list' object has no attribute 'split'", 'status': 'Failed'}