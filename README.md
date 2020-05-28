## Android Memory/Resource Leak Analysis

Requirements: \
[Maven](http://maven.apache.org/install.html) \
[Python 3](https://www.python.org/downloads/) (experiments only)

Setup:
```shell script
git clone https://github.com/guitard0g/memleaks_flowdroid.git
cd memleaks_flowdroid
./configure.sh
```

How to run:
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

Running on experiment datasets:

Memory Leaks:
```
./experiment_memleaks.sh <platforms_dir> [-t <timeout>] 
```

Resource Leaks:
```
./experiment_resleaks.sh <platforms_dir> [-t <timeout>] 
```
