#include "Python.h"

// hawkey
#include "src/package_internal.h"
#include "src/packagelist.h"
#include "iutil-py.h"
#include "sack-py.h"

PyObject *
packagelist_to_pylist(HyPackageList plist, PyObject *sack)
{
    HyPackageListIter iter;
    HyPackage cpkg;
    PyObject *package;
    PyObject *list;
    PyObject *retval;

    list = PyList_New(0);
    if (list == NULL)
	return NULL;
    retval = list;
    iter = hy_packagelist_iter_create(plist);
    while ((cpkg = hy_packagelist_iter_next(iter)) != NULL) {
	package = new_package(sack, package_id(cpkg));
	if (package == NULL) {
	    retval = NULL;
	    break;
	}
	if (PyList_Append(list, package) == -1) {
	    retval = NULL;
	    break;
	}
    }
    hy_packagelist_iter_free(iter);
    if (retval)
	return retval;
    /* return error */
    Py_DECREF(list);
    return NULL;
}