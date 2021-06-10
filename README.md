## VRF optimisations
Testing possible improvements for the VRF verification function. 
This code compiles using the `vrf_opts` [branch](https://github.com/input-output-hk/libsodium/tree/vrf_opts) 
of IOHK's `libsodium` fork.

To run tests:
```
make
./vrf_tests
```
which generates `Results.csv` file with the running times. `pandas` makes
it quite simple to analyse the data:
```python
python3
>>> import pandas as pd
>>> pd.read_csv('Results.csv')
# To get the mean of the different values
>>> pd.mean()
# To get the standard deviation
>>> pd.std()

```