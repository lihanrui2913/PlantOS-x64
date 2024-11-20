#include <math.h>
#include <sys/plant/types.h>
#include "libm.h"

double fabs(double x)
{
    union
    {
        double f;
        uint64_t i;
    } u = {x};
    u.i &= -1ULL / 2;
    return u.f;
}
