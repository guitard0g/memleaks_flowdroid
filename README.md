## Android Memory Leak Analysis

How to run:

Open the project inside of Intellij. Navigate to the App.java class. Press the 
run button to trigger a build. The output should say that the program requires
two program arguments. Go to Run then Edit Configurations. Add two
program arguments. The first argument will be the path to the APK you want to 
analyze. The second argument will be the path your android SDK directory. It 
should look something like "/home/<some_path>/android/sdk/platforms".
