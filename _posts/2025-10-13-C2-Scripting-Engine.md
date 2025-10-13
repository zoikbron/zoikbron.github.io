---
title: Building a C2 Framework - Scripting Engine
date: 2025-10-13 12:00:00 -500
categories: [malware development,red team,offensive tooling]
tags: [Rust,C2,pentesting,career,tips,tricks]
image:
  path: /assets/img/posts/c2/CoverC2.png
  alt: C2 Logo
---

## Scripting Engine

A scripting engine is a software component responsible for interpreting and executing scripts written in a specific scripting language. Unlike compiled languages, which are translated into machine code once during compilation, scripting languages are parsed and executed at runtime by the scripting engine.

A lot extensibles programs uses scripting languages to make the server do stuff without we needing to recompile every time we want to add a functionality

Lua is one of the most well known language for embbeding scripting into a program.
Others like Unreal Engine developed their own "Scripting Engine"

The same case with Cobalt Strike that uses it's own engine call Aggressor Script

>Aggressor Script is the spiritual successor to Cortana, the open source scripting engine in Armitage. Cortana was made possible by a contract through DARPA's Cyber Fast Track program. Cortana allows its users to extend Armitage and control the Metasploit Framework and its features through Armitage's team server. Cobalt Strike 3.0 is a ground-up rewrite of Cobalt Strike without Armitage as a foundation.


## Rhai-rs
During my research on integrating scripting engines into projects, with a particular focus on the Rust ecosystem, I came across the Rhai-rs project. After reviewing its documentation, examining the available types, and understanding its architecture, I found that it aligns perfectly with what I needed.

What is Rhai-rs?
> Rhai is an embedded scripting language and evaluation engine for Rust that gives a safe and easy way to add scripting to any application.

Here the most useful features for my case:
- Dynamic typing.
- Tight integration with native Rust functions and types, including getters/setters, methods and indexers.
- Freely pass Rust values into a script as variables/constants via an external Scope - all clonable Rust types are supported; no need to implement any special trait. Or tap directly into the variable resolution process.
- Built-in support for most common data types including booleans, integers, floating-point numbers (including Decimal), strings, Unicode characters, arrays (including packed byte arrays) and object maps.
- Easily call a script-defined function from Rust.
- Re-entrant scripting engine can be made Send + Sync (via the sync feature).
- Compile once to AST form for repeated evaluations.
- Scripts are optimized (useful for template-based machine-generated scripts).

### Implementing Rhai-rs

>Rhai is essentially a blocking, single-threaded engine. Therefore it does not provide an async API.

Based on this approach, we will follow the pattern recommended by the Rhai documentation. I have created two separate threads: one for the engine and one for the worker. The engine is responsible for registering functions, such as send_coff. This function is intended to invoke our implementation of send_coff; however, since the function is asynchronous, it cannot be called directly from the engine thread.

Instead, the engine communicates with the worker through a channel. The worker receives the request, matches it to the appropriate function call, executes it asynchronously, and then sends the result back through the channel. Similarly, our server communicates with the engines via a separate channel.

#### Workflow

Let'start with the engine thread:

The engine thread is initialized with three main components:

1. An engine command receiver for server-to-engine communication.

2. An API sender for engine-to-worker communication.


3. The scripts location where user-defined scripts reside.

Upon startup, the engine registers all the functions specified in its initialization. It then listens for messages on the command channel, matches them to the appropriate enum variant, performs the requested operation, and sends the result back to the caller using the provided reply sender.

```rust
while let Ok(cmd) = engine_rx.recv() {
        match cmd {
              EngineCmd::ListInteractive { reply } => {
                let list = if let Ok(map) = commands_interactive.read() {
                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect() } else { Vec::new() }; 
                let _ = reply.send(list);
            }
        }
    }
```

All registered functions exist within the engine, so the server only needs to be aware of the functions created via scripts. To facilitate this, a `Map` (from rhai-rs) is used to store dynamic values (`Dynamic`) effectively holding new commands along with a function pointer to execute their logic. These dynamic functions can leverage any previously registered engine functions.

The workflow for creating dynamic commands is as follows:
- Register a new function
```rust
 {   let tx = api_tx.clone();
        let ci = commands_interactive.clone();
        engine.register_fn("beacon_command_register", move |specs: Map |  {
            let script_cmd = arguments::register_command(specs);
            if let Ok(script_cmd) = script_cmd {
                if let Ok(mut map) = ci.write() { 
                    map.insert(script_cmd.name.clone(), script_cmd);
                }
            }
            let _ = tx.send(ApiCall::BuildCommands { commands: create_script_commands(ci.clone()), scope: CommandScope::Interactive });
    
        });
    }
```
- Parse the command map to generate new commands dynamically.

```rust
pub fn register_command(spec: Map) -> Result<ScriptCommand, String> {
    let name = spec.get("name").and_then(/*type cast*/).ok_or("missing name")?;
    let desc = spec.get("desc").and_then(/*type cast*/).unwrap_or_default();
 
 let args = spec.get("args").and_then(/*type cast*/).unwrap_or_default();
 let args = args.into_iter()
 .map(|m| Dynamic::try_cast::<Map>(m).unwrap())
 .map(|m| 
    ArgSpec {
    name: m.get("name").and_then(/*type cast*/).unwrap_or_default(),
    required: m.get("required").and_then(/*type cast*/).unwrap_or(false),
    default: m.get("default").and_then(/*type cast*/)
    .or_else(|| m.get("value").and_then(/*type cast*/)),
    value_parser: m.get("type").and_then(/*type cast*/),
    help: m.get("help").and_then(/*type cast*/),
    flag_type: m.get("flag_type").and_then(/*type cast*/).unwrap_or(false),
    num_args: m.get("num_args").and_then(/*type cast*/).unwrap_or(1),
    }
).collect::<Vec<_>>();

    let handler = spec.get("handler").and_then(|h| h.clone().try_cast::<FnPtr>()).ok_or("missing handler")?;

    Ok(ScriptCommand {/**/})
}
```
In the interactive mode:

- Arguments are converted into Dynamic values and stored in a `rhai::Array` (essentially a `Vec<Dynamic>`).
```rust
let mut results = Array::new()
 for arg in cmd.get_arguments() {
    let name = arg.get_id().as_str();
                        
     // Skip built-in help
        if name == "help" {
            continue;
                    }
                        
        let val_opt = matches
        .get_one::<Dynamic>(name)
        .cloned()
        .or_else(|| arg.get_default_values().iter().next().map(|s| Dynamic::from(s.to_string_lossy().to_string())));
                        
        match val_opt {
                Some(v) => results.push(v),
                None if arg.is_required_set() => missing_required.push(name.to_string()),
                    None => (),
                }
    }
```
- The command, along with its arguments and the function name, is passed to either `invoke_interactive()`, which communicate with the engine by sending the session ID, arguments, and a reply sender.

```rust
 pub async fn invoke_command_interactive(&self, name: &str, session_id: Option<&str>, args: Option<Array>) -> Result<Dynamic,String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.engine_tx.send(EngineCmd::InvokeInteractive { name: name.to_string(), session_id: session_id.map(|s| s.to_string()), args: args, reply: tx });
        rx.await.unwrap_or_else(|e| Err(e.to_string()))
    }

```

Inside the engine:

- The message is matched to either `InvokeInteractive` or `InvokeGlobal`.
```rust
enum EngineCmd {
    LoadAll,
    Emit { event: String, ctx: PlainContext },
    ListGlobal { reply: Sender<Vec<(String, String)>> },
    ListInteractive { reply: Sender<Vec<(String, ScriptCommand)>> },
    InvokeGlobal { name: String, session_id: Option<String>, args: String, reply: Sender<Result<Dynamic, String>> },
    InvokeInteractive { name: String, session_id: Option<String>, args: Option<Array>, reply: Sender<Result<Dynamic, String>> },
}
```

- The engine retrieves the function pointer from the map using the provided function name.
```rust
EngineCmd::InvokeInteractive { name, session_id, args , reply } => {
let fname_opt = if let Ok(map) = commands_interactive.read() { map.get(&name).map(|h| h.handler.clone()) } else { None };
if let Some(fname) = fname_opt {
let mut m = Map::new();
m.insert("session_id".into(), Dynamic::from(session_id.unwrap_or_default()));
m.insert("args".into(), Dynamic::from(args.unwrap_or_default()));
let r = call_fn(&engine, &asts, fname, m).map_err(|e| e);    
    let _ = reply.send(r);
} else { let _ = reply.send(Err(format!("command not found: {}", name))); }
            }
```

- It calls `call_fn()`, passing the session context (session ID and arguments), the function pointer, ASTs, and the engine reference, `call_fn()` executes the function and returns a `Result<Dynamic, String>`.

```rust
 let call_fn = |engine: &Engine, asts: &Vec<AST>, handler: FnPtr, ctx: Map| -> Result<Dynamic, String> {
        for ast in asts.iter() {
            let result = match handler.call::<Dynamic>(engine, ast, (Dynamic::from(ctx.clone()),)) {
                 Ok(info) => info, 
                 Err(e) => return Err(e.to_string()) };
            return Ok(result.into_shared().clone());
        }
        Err("function not found".to_string())
    };
```
- Finally, the engine sends the result back to the server, which converts the Dynamic into the expected type and proceeds with further processing.
```rust
cmd_id = match host.invoke_command_interactive(cmd.get_name(), Some(&resolved_id), Some(results)).await {
   Ok(cmd_id_a) => Some(cmd_id_a.as_int().unwrap_or_default() as i64),
   Err(e) => { eprintln!("Failed to send command: {}", e);  continue; }
    };
```

This represents just one use case of the scripting engine. It is also capable of emitting events on responses, requests, and other actions, which allows the creation of complete workflows. This part of the implementation is still under development, so I will not include it here.

#### Demo

`demo.rhai`

In this script, I created a command called exec, which executes a command within a session. The command requires a single argument (it does not accept flags like --flag). It also includes a name, a description, and a handler. The handler is defined in the script, receives the arguments, calls the send() function with those arguments, and then returns the cmd_id to the caller.
```rust
let map = #{
    name: "exec",
    desc: "Execute a command on a session",
    args: [
    #{ name: "cmd", required: true, help: "Command to run", flag_type: false, num_args: 1 },
    #{ name: "timeout", required: false, value: "5", help: "Timeout in seconds", flag_type: false, num_args: 1 }    ],
    handler: handler
};

fn handler(ctx) {
    let sid = ctx["session_id"];
    let args = ctx["args"];
    let cmd = args[0];
    let timeout = args[1];           
    let cmd_id = send(sid,"exec", cmd);             
    return cmd_id;
}
beacon_command_register(map);

```
Usage:

![Exec](/assets/img/posts/c2/Scripting/exec.png)

![Exec_help](/assets/img/posts/c2/Scripting/exec_help.png)

![Exec_Usage](/assets/img/posts/c2/Scripting/exec_usage.png)


#### New COFF command

`boff_demo.rhai`

In this script, I created a new command for sending a boff payload to the implant. This command leverages various engine-registered functions and introduces a refined definition for arguments, enabling proper parsing and conversion. Let’s break it down.

Argument Definition

In this command, we introduce a new argument property called type. This allows the command to parse arguments as one of the following types:

- `widestring`

- `short`

- `int`

- `utf8string`

Rust primitives like string (used by default if no type is specified)

Previously, using the legacy command system was error-prone because all arguments, including optional ones, had to be explicitly specified. With this new approach, optional arguments can be assigned default values via the value property. For example, if we want an argument to be null, we can simply set `value: ""`.

```rust
let map = #{
    name: "netlocalgroup",
    desc: "Get local groups members",
    args: [
    #{ name: "look_members", required: false, value: "0", help: "Look for groups or group members", type: "short", flag_type: true, num_args: 1 },
    #{ name: "server", required: true, help: "Server name", type: "widestring", flag_type: false, num_args: 1 },    
    #{ name: "groupname", required: false, value: "", help: "Group name", type: "widestring", flag_type: false, num_args: 1 }
       ],
    handler: handler
};

fn handler(ctx) {
    let sid = ctx["session_id"];
    let args = ctx["args"];
    let groupname = args[2].value;
    if groupname != "" {
        args[0] = TypedArg::short(1);
    }            
    let packed_args = pack_args(args);
    let bof_file = read_file("SA\\netlocalgroup\\netlocalgroup.x64.o",true);
    if bof_file.is_empty() {
        exit("Failed to read BOF file");
    }
    let cmd_id = send_coff(sid,bof_file,"go",packed_args);
    return cmd_id;
}
beacon_command_register(map);
```
Some arguments, such as `look_members`, may depend on other optional arguments like groupname. In the handler function, we can dynamically adjust their values. For instance, if the third argument is not null, we update `look_members` to `1` so the command behaves as expected, targeting the members of the specified group. Also `look_members` is specified as `flag_type: true` so at the moment of command creation we dont have to put the look_members to 0 neither 1 unless we explicitly specified `--look-members`

Handler Functions

The command’s handler also uses three registered engine functions:

`pack_args()` – Collects all arguments and packs them into a `Vec<u8>`. This is a wrapper around `pack_args_ordered()` discussed previously.

`read_file()` – Reads the content of a file. The additional boolean parameter allows reading from specific predefined locations without requiring the full file path.

`send_coff()` – A wrapper around `send_coff_to_session()`. It sends the payload to the session, specifying the session ID, the binary blob of the boff, the entry point, and the packed arguments.

we can also return errors with `exit()` which means our server will expect a `Result<Dynamic,String>` either an exit() with a string or a return with a Dynamic

Preview

![NetLocalGroup](/assets/img/posts/c2/Scripting/netlocalgroup.png)

![NetLocalGroup_help](/assets/img/posts/c2/Scripting/netlocalgroup_help.png)

![netlocalgroup_usage1](/assets/img/posts/c2/Scripting/netlocalgroup_usage.png)

![netlocalgroup_usage2](/assets/img/posts/c2/Scripting/netlocalgroup_usage2.png)






