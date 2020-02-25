# TODO: tests others jitter/arch

from api import test_api
test_api()

from propagation import test_taint_propagation
test_taint_propagation()

from propagation_precision import test_propagation_precision
test_propagation_precision()

from callbacks import test_callbacks
test_callbacks()
