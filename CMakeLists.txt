# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.1)
project(ndprbrd)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED true)

find_package(Qt5Network)
add_executable(ndprbrd ndprbrd.cpp)
target_link_libraries(ndprbrd Qt5::Network)

include(GNUInstallDirs)
install(TARGETS ndprbrd RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
