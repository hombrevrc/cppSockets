## C++ ssl socket servers - working examples

#### Compile
g++ ssl-fork.cpp -std=c++11 -lssl -lcrypto -o start-fork 
<br>
g++ ssl-thread.cpp -std=c++11 -lssl -lcrypto -pthread -o start-thread

#### Run
chmod +x start-fork <br>
./start-fork
<br>
chmod +x start-thread <br>
./start-thread

#### Test with openssl client
openssl s_client -connect localhost:999

#### Install 
apt-get install libssl-dev openssl g++
