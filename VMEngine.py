import pyvex
from angr.engines import UberEngine


class VmEngine(UberEngine):

    def _handle_vex_expr_RdTmp(self, expr: pyvex.expr.RdTmp):
        return super()._handle_vex_expr_RdTmp(expr)
