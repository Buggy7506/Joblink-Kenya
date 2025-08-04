C:\Users\CIBU\Desktop\joblink\New folder (6)\joblink\core\views.py changed, reloading.
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
August 04, 2025 - 12:17:19
Django version 5.1.7, using settings 'joblink.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.

Internal Server Error: /post-job/
Traceback (most recent call last):
  File "C:\Users\CIBU\AppData\Local\Programs\Python\Python313\Lib\site-packages\django\core\handlers\exception.py", line 55, in inner
    response = get_response(request)
  File "C:\Users\CIBU\AppData\Local\Programs\Python\Python313\Lib\site-packages\django\core\handlers\base.py", line 197, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
  File "C:\Users\CIBU\AppData\Local\Programs\Python\Python313\Lib\site-packages\django\contrib\auth\decorators.py", line 60, in _view_wrapper
    return view_func(request, *args, **kwargs)
  File "C:\Users\CIBU\Desktop\joblink\New folder (6)\joblink\core\views.py", line 146, in post_job
    job.employer = request.user
    ^^^^^^^^^^^^
AttributeError: 'NoneType' object has no attribute 'employer' and no __dict__ for setting new attributes
[04/Aug/2025 12:21:10] "POST /post-job/ HTTP/1.1" 500 70004








