/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * Licensed under the GNU Lesser General Public License Version 2.1
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef HY_SUBJECT_H
#define HY_SUBJECT_H

#include <stdlib.h>
#include <solv/util.h>
#include "dnf-types.h"
#include "hy-types.h"
#include "hy-nevra.h"

#include <glib.h>

G_BEGIN_DECLS

#ifdef __cplusplus
enum _HyForm :short {
#else
enum _HyForm {
#endif
    HY_FORM_NEVRA = 1,
    HY_FORM_NEVR = 2,
    HY_FORM_NEV = 3,
    HY_FORM_NA = 4,
    HY_FORM_NAME = 5,
    _HY_FORM_STOP_ = -1
};

struct _HyPossibilities {
    HySubject subject;
    DnfSack *sack;
    int flags;
    HyForm *forms;
    int current;
    int type;
};

extern HyForm HY_FORMS_MOST_SPEC[];
extern HyForm HY_FORMS_REAL[];

HySubject hy_subject_create(const char * pattern);
void hy_subject_free(HySubject subject);
void hy_possibilities_free(HyPossibilities iter);
HyPossibilities hy_subject_reldep_possibilities_real(HySubject subject,
    DnfSack *sack, int flags);
int hy_possibilities_next_reldep(HyPossibilities iter, DnfReldep **out_reldep);
HyPossibilities hy_subject_nevra_possibilities(HySubject subject,
    HyForm *forms);
HyPossibilities hy_subject_nevra_possibilities_real(HySubject subject,
    HyForm *forms, DnfSack *sack, int flags);
int hy_possibilities_next_nevra(HyPossibilities iter, HyNevra *out_nevra);

HyQuery hy_subject_get_best_query(HySubject subject, DnfSack *sack, gboolean with_provides);
HySelector hy_subject_get_best_selector(HySubject subject, DnfSack *sack);

G_END_DECLS

#endif
