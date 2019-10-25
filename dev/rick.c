#include "lib_rick.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <jwt.h>





#define TS_CONST    1475980545L



void main(){
    fun();

    FILE *out;
    jwt_t *jwt = NULL;
    int ret = 0;

            jwt_decode(&jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImlzcyI6IjVkMTk1MWMyNDcyNjkwMzQyMjI0Yjk5ZiJ9.e30.ZpCkhhr3_ttfmkXqShnbOn4p5nnSlolCWzMoMury6wI", (unsigned char *)"red cat wears hat", 0);
            const char *account = jwt_get_grant(jwt, "iss");
            jwt_free(jwt);
            printf(account);


}
