# pintools
A collection of PIN tools that I've created.

Download PIN source from [Intel's
website](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads). 
Unzip to a directory that I'll call $PINDIR.

# Building
* copy to pin source tree:
```bash
cp -R HeapVerifer $PINDIR/source/tools
```
* 32-bit
```bash
cd $PINDIR/source/tools/HeapVerifier
make TARGET=ia32 clean
make TARGET=ia32
```
* 64-bit
```bash
cd $PINDIR/source/tools/HeapVerifier
make TARGET=intel64 clean
make TARGET=intel64
```

# Running
* 32-bit
```bash
$PINDIR/pin -t $PINDIR/source/tools/HeapVerifier/obj-ia32/HeapVerifier.so -- ./buggyapp
```
* 64-bit
```bash
$PINDIR/pin -t $PINDIR/source/tools/HeapVerifier/obj-intel64/HeapVerifier.so -- ./buggyapp
```
