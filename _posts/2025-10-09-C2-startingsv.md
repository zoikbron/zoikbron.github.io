---
title: Building a C2 Framework - Server Design
date: 2025-10-09 12:00:00 -500
categories: [malware development,red team,offensive tooling]
tags: [Rust,C2,pentesting,career,tips,tricks]
image:
  path: /assets/img/posts/c2/CoverC2.png
  alt: C2 Logo
---

## Defining basics for the server

In this moment, I was thinking about what I wanted to do and then maybe escalate it to something bigger.


The server will be:

Asynchronous (non-blocking I/O and task scheduling)
- REPL CLI for operator interaction (commands, history, completion)
- JobManager to spawn, track, await, cancel, and inspect async tasks/operations
- Listener manager to host multiple protocol listeners configuration and listener instances (TCP, HTTP/S, gRPC, SMB, etc.)
- Multi-protocol session management
- Detachable sessions — be able to exit interactive mode without destroying session state
- Interactive session mode to send commands and receive live output from implants
- Command delivery / retrieval (send task, retrieve result from implant)
- Health checks and telemetry for sessions and listeners
- Embbeded Scripting Languange

## Design
![Design](/assets/img/posts/c2/Server%20Basics/Design.png)

####  System Architecture Overview

This design represents a **C2-style server framework** where the **`ServerManager`** orchestrates communication between multiple components:
- **Sessions** (active connections/clients)  
- **Listeners** (protocol-specific interfaces)  
- **Jobs/Commands** (tasks or payloads to execute)  
- **Printers/ScriptHosts** (for output and scripting logic)

####  High-Level Concept

The system centers around the `ServerManager`, which coordinates:
- Active **sessions** through the `SessionManager`
- Background Tasks through the `JobManager`
- Incoming **connections** through the `ListenerManager`
- **scripting logic** through the `ScriptHost`


####  Core Components

######  `ServerManager`
**Role:** The central orchestrator.

**Responsibilities:**
- Initializes all sub-managers (`SessionManager`, `ListenerManager`, `JobManager`, etc.)
- Dispatches commands to sessions.
- Handles result propagation when sessions report back.
- On connection, forwards the socket to `SessionManager` to create a new `Session`.
- Routes output through `ExternalPrinter`.

**Internals:**
```rust
pub struct ServerManager {
    session_manager: Arc<SessionMan>,
    script_host: Arc<EngineHost>,
    pub job_mgr: Mutex<JobMan>,
    pub listener_mgr: ListenerMan,
}
```
#####  `SessionManager`
**Role:** Manages all active sessions.

- Handles the Session API to communicate with the underlaying session_manager

##### `MultiProtocolSession`
**Role:** Hold all data, notifiers, queues, protocols type, ... about the implant.

**Responsibilities:**
- Processes incoming/outgoing commands.
- Stores sessions in a thread-safe `HashMap<SessionId, Session>`.
- Routes incoming results/events to the correct session by ID.
- Each session has a unique **notifier** channel.
- Emits results through its **notifier channel**.

```ProtocolSession Trait```
- Implements an interface for protocol-specific behavior.

#####  `ListenerManager`
**Role:** Manages all network listeners configuration and hold all listener jobs.

**Responsibilities:**
- Monitors protocol listeners (HTTP, SMB, TCP, etc.)
- Hold listeners jobs

**Conceptually:**
```
Incoming Connection → ListenerManager → SessionManager → Session
```
#####  `JobManager`
**Role:** Queues and manages task execution.

- Receives commands from operators or scripts.
- Spawn background task (Listeners, Scripts)
- Tracks background tasks

Acts as a **scheduler** for distributed job execution.

#####  `ScriptHost`
**Role:** Provides optional dynamic scripting capabilities using Rhai-rs.

- Enables scripting and automation of jobs, sessions, or listeners.
- Enable dynamic command creation.

##### Event Flow

The typical runtime flow looks like this:

1. **Startup**  
   `ServerManager` initializes all subcomponents and starts listeners.

2. **Connection Arrives**  
   A listener accepts a new client → `SessionManager` creates a `Session`.

3. **Command Sent**  
   A command is built and queued → assigned to a session → implant retrieves → implant executes it.

4. **Result Received**  
   Implant emits a result → server receive new result → pushes it through its **notifier** → `Session`.

5. **Result Broadcast**  
   `Session mode` awaits for the result and look for the right id to print results.
   `Beacon mode` do not await.

## Developing

I'd start with the `JobManager` then the `ListenerManager`

### Job Manager
For the `JobManager` I'd just created 2 structs `Job` which contains the JoinHandle and some description about the job.
```rust
pub struct Job{
 handle: JoinHandle<()>,
 description: String,
}
```

With the `JobManager` struct you can decide which collection do you want to use
While data structures like Vec and BTreeMap can offer better cache locality and iteration performance in this scenario, these differences are minimal for the current use case, where the dataset is small and access patterns are straightforward. In this context, using a HashMap is both simpler and more practical — it provides efficient key-based lookups, which aligns well with the component’s ID-based access pattern.

```rust
struct JobManager{
   jobs: Hashmap<usize,Job>
   next_id: usize
}
```
This is a very nice approach to get a JobManager it simply will spawn threads with tokio. So for that matter I just created a wrapper around tokio::spawn for storing handles and giving some description
> Later on may a add some metadata for debugging and logging purposes.
{: .prompt-info}

```rust
pub fn spawn<F>(&mut self,fut: F,description: &str) -> usize
where F: std::future::Future<Output = ()> + Send + 'static {
 let id = self.next_id;
 self.next_id += 1;
 let handle = tokio::spawn(fut);
 self.jobs.insert(id, Job { handle, description: info.to_string() });
 println!("Spawned job {}:", id);
 id
} 
```
Also added foreground function and cancel function.

>Later on, this was updated to gracefully stop the task through oneshot channels
{: .prompt-info}


### Listener Manager
Here the approach is basically the same as the JobManager, one struct will contain the config and the manager a hashmap of configs.

> Again probably we won't have a lot listeners which make using Vector a better approach for performance.
{: .prompt-info}
```rust
pub enum ProtocolType {
    Grpc,
    Tcp,
    Http,
    WebSocket,
}

pub struct Config {
    pub id: usize,
    pub protocol_type: ProtocolType,
    pub bind_ip: IpAddr,
    pub bind_port: u16,
    pub enabled: bool,
    pub options: HashMap<String, String>,
}


pub struct ListenerManager {
    listeners: HashMap<usize, Config>,
    job_mgr: JobManager
}
```
In the current design, each listener is identified by a unique string ID. The `ListenerManager` is responsible for holding both the configuration and runtime state (jobs) of all active listeners.

The options field is reserved for future use and will allow specifying runtime parameters such as URL endpoints, user agents, polling intervals, and other customizable settings.

The protocol_type field may later evolve into a more general `payload_type`, enabling support for both staged and stageless payload delivery.

Conceptually, the `ListenerManager` serves as the central component managing all listener-specific configurations and their associated async jobs. These jobs are spawned and tracked through the `JobManager`, while the `ServerManager` acts as the top-level orchestrator, delegating listener-related task creation, management, and shutdown to the `ListenerManager` and its internal job manager.

So let's create the constructor for `ListenerConfig`
```rust
impl ListenerConfig {
    pub fn new(name: String, protocol_type: ProtocolType, bind_ip: IpAddr, bind_port: u16) -> Self {
        Self {
            name,
            protocol_type,
            bind_ip,
            bind_port,
            enabled: false,
            options: HashMap::new(),
        }
    }
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_ip, self.bind_port)
    }

}
```
Added an abstraction for spawning new listeners wrapping the JobManager functions.

```rust
 pub fn spawn<F>(&mut self, fut: F, info: &str) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.job_mgr.spawn(fut, info)
    }
```
Once we create the config we can add it to our listener
```rust
pub fn add_listener(&mut self, config: ListenerConfig) -> Result<String, String> {
        let name = config.name.clone();
        
        // Check for name conflicts
        if self.listeners.contains_key(&name) {
            return Err(format!("Listener '{}' already exists", name));
        }

        // Check for port conflicts
        let socket_addr = config.socket_addr();
        for (existing_name, existing_config) in &self.listeners {
            if existing_config.socket_addr() == socket_addr && existing_config.enabled {
                return Err(format!("Port {} is already in use by listener '{}'", 
                    socket_addr.port(), existing_name));
            }
        }

        self.listeners.insert(name.clone(), config);s
        Ok(name)
    }
```
We can add others function like name generator, enable_listener, etc.

To build the listener configuration we do something like this:
```rust
 pub fn create_and_start_listener(&mut self, protocol_type: ProtocolType, bind_ip: IpAddr, bind_port: u16) -> Result<String, String> {
        let name = self.generate_name(&protocol_type);
        let config = ListenerConfig::new(name.clone(), protocol_type, bind_ip, bind_port);
        
        self.add_listener(config)?;
        self.enable_listener(&name)?;
        Ok(name)
    }
```
>`enable_listener` turn on the bool for the enabled field in the listener config & `generate_name` just take the protocol type, use it as prefix and increment a counter if the key already exist.
{: .prompt-tip}

### REPL

For this matter I used some packages that makes everything easier, `rustyline`, `clap` for commands parsing.
This works great for adding history, completion, etc. I did'nt get too much on that, just simple history and that's it for now.

```rust
loop {
       
        let prompt = match current_module {
            Some(m) => format!("[{}]> ", m.name),
            None => "[zoik]> ".to_string(),
        };
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(_) => break,
        };
        let _ = rl.add_history_entry(line.as_str());
}
let tokens: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
if tokens.is_empty() { continue; }
```
At first, I used a simple split whitespace to get all tokens and match the first token with some command and then pass the others tokens to the clap parser.

With clap you can create structs and use them to define arguments and options

```rust
#[derive(Parser, Debug)]
pub struct AddLisArgs {
    pub name: String,
    #[arg(value_enum)]
    pub protocol_type: ProtocolType,
    pub bind_ip: IpAddr,
    pub bind_port: Option<u16>,
}

match tokens[0].as_str(){
    "add_listener" => { 
        match AddLisArgs::try_parse_from(args) {
                Ok(parsed) => {
                    let pt: ProtocolType = parsed.protocol_type.into();
                    let port = parsed.bind_port.unwrap_or_else(|| 8000);
                    let config = ListenerConfig::new(parsed.name.clone(), pt, parsed.bind_ip, port);
                }
                Err(e) => eprintln!("{}", e),
            }

    }
}
```
First I added a help command to the REPL, so it shows pretty much the commands available. All specific managers related commands were put in their own source file I just pass the tokens to a handle and it matches to the right command.

For example in the listener manager command we have:
- `listeners`
Displays a list of all registered listeners, including their IDs, protocol types, configurations, and current runtime status (enabled, disabled, or running).

- `running`  List the jobs.

- `add_listener`
Registers a new listener configuration in the system. This creates the listener entry but does not start it immediately. 

- `enable`
Enables a previously added listener, marking it as active and ready to start. This does not spawn the job yet, it simply makes the listener available for activation.

- `disable`
Disables a listener, preventing it from being started or accepting new connections. If the listener is currently running, it will first be stopped gracefully.

- `start_listener`
Spawns and starts a new (for now) listener as an asynchronous job through the internal job manager. Once started, the listener begins handling incoming connections or requests according to its configuration.
s
- `stop_listener`
Gracefully stops a running listener, signaling its associated async job to shut down and releasing any related resources.

Some of this commands just uses the functions we already seen, others are new functions added to the `ListenerManager` implementation.

I tried to not embbeded actual code here and just call some functions so it is easier later to create a GUI.

Below an example:

![Help](/assets/img/posts/c2/Server%20Basics/help.png)

Later on I'll talk about the actual handlers implementations, but here a preview in how it works.
![Preview](/assets/img/posts/c2/Server%20Basics/example.png)

This is all for this one the next one will be entirely about `SessionManager`.

### What's been done so far?

- Select tokio as runtime
- `JobManager` with spawn, store and cancel task.
- `ListenerManager` create listener configs store and implemented one job manager for listeners
- A simple REPL so we can add a few listener related commands like start,stop,list running listeners, enable configs, list all configs.
















