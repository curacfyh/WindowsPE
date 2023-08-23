#include "Utils.h"

unsigned int align(const unsigned int size, const unsigned int alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}