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

We are also studying the possibility of not relying on a fork of libsodium,
and insted use it as a library. For that, we also benchmark the performance
of the operations available in the API vs the internal operations. A run 
with 100_000 iterations get us the following numbers. 

```python
>>> data.mean()                                                           
 verif            0.000219                                                
 verif_try_inc    0.000207                                                
 verif_opt        0.000160                                                
 api_mul          0.000099                                                
 internal_mul     0.000052
```

`verif` is the implementation used currently, with no optimisations. We 
can see that using try and increment technique, `verif_try_inc`, to 
compute `hash_to_curve`, instead of `elligator`, gives a 
slight improvement. However, it is to note that this would require a
hard fork. 

`verif_opt` runs the VRF verification with variable time operations. We 
can see a considerable improvement in this case. To make matters better
this would be compatible with the current node implementation---we would
simply need to change the verification function. 

Finally, the operations made available in the api, `api_mul`,
show to perform much worse than the internal ones, `internal_mul`. This 
is due to the fact that the api assumes the caller does not "know what
it is doing", and before performing the operation makes a bunch of 
tests and conversions. 

### ToDo
- [ ] Batch verification (needs slight modification of VRF)