#!/usr/bin/env bash
mkdir config_libs
cd config_libs
git clone https://github.com/guitard0g/soot.git
cd soot
git checkout scene-rebuild-support
mvn -DskipTests install
cd ..
git clone https://github.com/guitard0g/FlowDroid.git
cd FlowDroid
git checkout scene-rebuild-support
mvn -DskipTests install
cd ..
