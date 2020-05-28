## Android Memory/Resource Leak Analysis

Requirements: \
[Maven](http://maven.apache.org/install.html) \
[Python 3](https://www.python.org/downloads/) (experiments only)

#### Setup:
```shell script
git clone https://github.com/guitard0g/memleaks_flowdroid.git
cd memleaks_flowdroid
./configure.sh
```

#### How to run
```
./run.sh -a <apk_file> -p <platforms_dir> [-t <timeout>] [-r] 
```
Program arguments
```
  -a,--apk <arg>         path to APK file to analyze
  -p,--platforms <arg>   path to android platforms directory
  -r,--resource          flag to switch to system resource analysis
  -t,--timeout <arg>     Timeout in minutes for the dataflow analysis
```

#### Running on experiment datasets

Memory Leaks:
```
./experiment_memleaks.sh <platforms_dir> [-t <timeout>] 
```

Resource Leaks:
```
./experiment_resleaks.sh <platforms_dir> [-t <timeout>] 
```

#### Implementation Overview

The implementation is contained in three Java files:

- App.java: the main class that calls the instrumentation and then runs dataflow analysis on the the instrumented APK
- Instrument.java: the implementation of all instrumentation and related utility functions, this is where the majority of type and context analysis happens
- CustomSourceSinkProvider.java: This is a Soot/FlowDroid specific source sink provider that we use so that we can specify our own sources and sinks however we want

#### What types of bugs we currently detect
Relevant resources to read:
- Memory leak examples: [NimbleDroid: Ways your Android app can leak memory](https://blog.nimbledroid.com/2016/05/23/memory-leaks.html)
- Resource leaks baseline and background info: [Droidleaks](https://yepangliu.github.io/files/droidleaks.pdf)
- Context leaks, what they are and how to determine them: [Static analysis of context leaks](https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=5654&context=sis_research)

This project aims to detect some of the most common types of memory leaks and resource leaks in Android applications.

Memory leaks are typically caused by the programmer not being cautious of how the Android runtime handles [lifecycles of 
Activities](https://developer.android.com/guide/components/activities/activity-lifecycle). The point of the runtime 
automatically managing lifecycles is so that if an app uses too much memory, then the Android runtime can garbage collect
some of the larger objects on the heap to free up space. The largest objects on the heap are typically user interface related
objects. We can identify these user interface objects by looking for contexts or context containers. What we do is look 
all cases where the programmer might cause a context to be inelligible for garbage collection, despite it reaching the end
of its lifecycle. The most common cases of this are specified in the NimbleDroid blog post. How we define contexts and 
context containers is defined in the Context leaks paper. 

Resource leaks are caused by a programmer opening some limited system resource (e.g. camera, database or db cursor, file handles, etc.)
and then not properly releasing that resource. You can find an in-depth discussion of this in the Droidleaks paper listed above.

#### How we detect these leaks
Our implementation offers the option to search for resource leaks or memory leaks when you run the program via the inclusion
or exclusion of the `--resource` or `-r` flag. 

##### Memory leaks

We divide memory leaks into two categories:
- Static variables that hold a value of a context or context container
- Anonymous Asynchronous/Thread objects that will persist a reference to a context or context container when it is created
because of its outer class instance 

Static variable leaks require us to instrument all cases where a static variable that can store a context/context container is assigned 
to a new value or to null. We instrument a variable being set to a value as a SOURCE and we instrument a variable being set to 
null as a SINK. Once we have instrumented all of these instructions, we run a standard dataflow analysis with our sources 
and sinks and then look at the results. If an instrumented source instruction (i.e. a static variable being assigned a nonnull value)
does NOT have a dataflow path to any instrumented sink, then we deduce that the static variable may cause a leak. This is 
because the variable can potentially hold a reference to a context that is never set to null, thus that context can never be garbage collected.

Anonymous thread-like objects that are inner classes of a context/context container are immediately seen as potential leaks.
This is because we don't know how long that thread will be executing and so we assume it may persist a reference to its outer 
class indefinitely. Because its outer class is a context instance, it may therefore cause a leak.

##### Resource leaks

We detect resource leaks similarly to how we detect static variable memory leaks. We first maintain a list of all the 
Java classes that we consider to be resources (i.e. an instance of this class will be an instance of a resource). Then 
we look for all instructions where one of these objects (or subclass) is created and instrument those instructions as 
SOURCES. Then we look for any instruction that calls an instance method on a resource object. If that invoked method has a 
name that indicates a closing operation (e.g. cursor.close(), Camera.close()), then we instrument that instruction as a 
SINK for that object. We then run a dataflow analysis to see where paths are found from sources to sinks. If a SOURCE
instruction does not flow to any corresponding SINK, then we determine there is a leak and that resource is reported as 
not properly closed. 

NOTE: There are instances where a resource object may be automatically managed. For instance, if a database object is created
with a SQLiteOpenHelper, then we should not track that database object because it will be closed automatically. A trickier
case occurs when the developer uses a method such as `startManagingCursor()`. If a cursor object is passed into this method,
then the runtime will automatically close it. Luckily we can easily circumvent this issue by instrumenting that special method
with a SINK so that we know whatever cursor object is passed to that method is properly closed. 
 

#### TODO

The one and largest todo for this project is to decrease false negatives. There are many cases where we cannot detect a leak
because our dataflow analysis will ONLY analyze code that it determines to be reachable from a program entrypoint (such as
`onCreate()`, `onStart()`, etc.). In order to do this you will need to find a way to instrument the code in order to make 
those unreachable methods reachable again. The most reasonable method of approach would be to find an entrypoint of the 
program and then instrument that entrypoint with an instruction that invokes any unreachable method. For convenience I 
have included code below that will show you which methods are and are not reachable:

```Java
// This code will get you all REACHABLE methods in the current Soot Scene
public HashSet<SootMethod> getReachableMethods() {
    // The callgraph will only give us reachable source and target methods
    CallGraph cg = Scene.v().getCallGraph();
    HashSet<SootMethod> methods = new HashSet<>();

    for (Edge e : cg) {
            methods.add(e.tgt());
            methods.add(e.src());
    }

    return methods
}

// This code will get you all methods in the current Soot Scene whether reachable or not
public HashSet<SootMethod> getAllMethods() {
    HashSet<SootMethod> methods = new HashSet<>();

    // Traverse all app classes    
    for(SootClass c: Scene.v().getApplicationClasses()) {
        // Traverse all methods
        for (SootMethod m : c.getMethods()) {
            methods.add(m)            
        }
    }

    return methods;
}

// You might combine the above methods to get unreachable methods like this
public HashSet<SootMethod> getUnreachableMethods() {
    HashSet<SootMethod> allMethods = getAllMethods();
    HashSet<SootMethod> reachableMethods = getReachableMethods;
    // set difference
    allMethods.removeAll(reachableMethods);
    return allMethods;
}
```
