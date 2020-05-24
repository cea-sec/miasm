#ifndef MIASM_RT_EXPORT_H
#define MIASM_RT_EXPORT_H

#ifdef _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT __attribute__((visibility("default")))
#endif

#endif
