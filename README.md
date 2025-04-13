# IDA Objc Helper
A plugin for IDA Pro 9.0+ to help with Objective-C code analysis.

## Supported features
- Hide memory management functions - `objc_retain`, `objc_release`, `objc_autorelease`, `objc_retainAutoreleasedReturnValue`. 
  - Optimize `_objc_storeStrong` to an assignment.
- Remove `__break` calls.
- collapse `__os_log_impl` calls.
- Hide selectors of Objective-c calls.
- When in Obj-C method, Ctrl+4 will show xrefs to the selector.

## Installation
1. clone the repo.
2. symlink `src` folder into your IDA Pro plugins folder:
    - on unix: `~/.idapro/plugins/`
    - on windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins`. `mklink /d` command can be used to create a symlink.
3. Restart IDA. 

## Examples
### Remove `__break`
Before:
```c
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
```

After: removed.

### Hide selectors of Obj-C calls
Before:
```c
   -[NSFileManager removeItemAtPath:error:](
      +[NSFileManager defaultManager](&OBJC_CLASS___NSFileManager, "defaultManager"),
      "removeItemAtPath:error:",
      +[NSString stringWithUTF8String:](&OBJC_CLASS___NSString, "stringWithUTF8String:", *(_QWORD *)&buf[v5]),
      0LL);
```

After:
```c
   -[NSFileManager removeItemAtPath:error:](
      +[NSFileManager defaultManager](&OBJC_CLASS___NSFileManager),
      +[NSString stringWithUTF8String:](&OBJC_CLASS___NSString, *(_QWORD *)&buf[v5]),
      0LL);
```

### Collapse `os_log`
Before:

```c
  v9 = gLogObjects;
  v10 = gNumLogObjects;
  if ( gLogObjects && gNumLogObjects >= 46 )
  {
    v11 = *(NSObject **)(gLogObjects + 360);
  }
  else
  {
    v11 = (NSObject *)&_os_log_default;
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
    if ( os_log_type_enabled(oslog: (os_log_t)&_os_log_default, type: OS_LOG_TYPE_ERROR) )
    {
      *(_DWORD *)buf = 134218240;
      *(_QWORD *)v54 = v9;
      *(_WORD *)&v54[8] = 1024;
      *(_DWORD *)&v54[10] = v10;
      if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
        __break(0xC471u);
      _os_log_error_impl(
        dso: (void *)&_mh_execute_header,
        log: (os_log_t)&_os_log_default,
        type: OS_LOG_TYPE_ERROR,
        format: "Make sure you have called init_logging()!\ngLogObjects: %p, gNumLogObjects: %d",
        buf: buf,
        size: 0x12u);
    }
  }
  if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
    __break(0xC471u);
  if ( os_log_type_enabled(oslog: v11, type: OS_LOG_TYPE_INFO) )
  {
    if ( a1 )
      v12 = *(_QWORD *)(a1 + 8);
    else
      v12 = 0LL;
    *(_DWORD *)buf = 138412290;
    *(_QWORD *)v54 = v12;
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
    _os_log_impl(
      dso: (void *)&_mh_execute_header,
      log: v11,
      type: OS_LOG_TYPE_INFO,
      format: "Random log %@",
      buf: buf,
      size: 0xCu);
  }
```

after:
```c
  if ( oslog_info_enabled() )
  {
    if ( a1 )
      v4 = *(_QWORD *)(a1 + 8);
    else
      v4 = 0LL;
    oslog_info("Random log %@", v4);
  }
```

## Development
In order to have autocomplete while developing, you need to add IDA's include folder ( `$IDA_INSTALLATION/python/3` ) to your IDE.
- on Visual Studio code you can add the folder to the analyzer's extra paths in the `settings.json` file:
```json
{
  "python.analysis.extraPaths": [
    "$IDA_INSTALLATION\\python\\3"
  ]
}
```
- on PyCharm you can add the folder to the interpreter's paths in the project settings. 
  Alternatively, you can create `idapython.pth` in `$VENV_FOLDER/Lib/site-packages` and add the path to it.

Inside IDA, you can use `objchelper.reload()` to reload the plugin during development.