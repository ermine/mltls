#define Unit(x) ((x), Val_unit)

#define ML_1(name, conv, retval)                                        \
  CAMLprim value ml_##name(value v) {return retval (name(conv(v)));}

#define ML_2(name, conv1, conv2, retval)              \
  CAMLprim value ml_##name(value v1, value v2) { \
    return retval (name(conv1(v1), conv2(v2))); }

#define ML_3(name, conv1, conv2, conv3, retval)                 \
  CAMLprim value ml_##name(value v1, value v2, value v3) { \
    return retval (name(conv1(v1), conv2(v2), conv3(v3))); }
