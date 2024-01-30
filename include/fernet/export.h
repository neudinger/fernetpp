
#ifndef FERNET_EXPORT_H
#define FERNET_EXPORT_H

#ifdef FERNET_STATIC_DEFINE
#  define FERNET_EXPORT
#  define FERNET_NO_EXPORT
#else
#  ifndef FERNET_EXPORT
#    ifdef Fernet_EXPORTS
        /* We are building this library */
#      define FERNET_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define FERNET_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef FERNET_NO_EXPORT
#    define FERNET_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef FERNET_DEPRECATED
#  define FERNET_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef FERNET_DEPRECATED_EXPORT
#  define FERNET_DEPRECATED_EXPORT FERNET_EXPORT FERNET_DEPRECATED
#endif

#ifndef FERNET_DEPRECATED_NO_EXPORT
#  define FERNET_DEPRECATED_NO_EXPORT FERNET_NO_EXPORT FERNET_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef FERNET_NO_DEPRECATED
#    define FERNET_NO_DEPRECATED
#  endif
#endif

#endif /* FERNET_EXPORT_H */
