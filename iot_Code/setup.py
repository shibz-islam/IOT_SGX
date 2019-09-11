from distutils.core import setup, Extension
setup(name = 'myModule', version = '1.0', ext_modules = [Extension('myModule', ['test.c'])])
setup(name = 'cryptoTestModule', version = '1.0', ext_modules = [Extension('cryptoTestModule', sources = ['cryptoTest.c'], libraries = ['ssl', 'crypto'])])