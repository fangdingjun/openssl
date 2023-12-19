%include "typemaps.i"

%typemap(gotype) (char *OUTCHARBUF, int len) %{[]byte%}
%typemap(in) (char *OUTCHARBUF, int len) {
    if ($input.len <= 0 || $input.cap <= 0){
        $1=NULL;
    }else{
        $1=(char *)malloc($input.cap);
        $2=$input.cap;
    }
}
%typemap(argout) (char *OUTCHARBUF, int len){
    if ($1 != NULL){
        memcpy($input.array, $1, $input.cap);
    }
}
%typemap(freearg) (char *OUTCHARBUF, int len){
    if($1 != NULL){
        free($1);
    }
}

%typemap(gotype) (void *inbuf, int len) %{[]byte%}
%typemap(in) (void *inbuf, int len) {
    if ($input.len <= 0 || $input.cap <= 0){
        $1=NULL;
    }else{
        $1=(void *)malloc($input.cap);
        $2=$input.cap;
    }
}
%typemap(argout) (void *inbuf, int len){
    if ($1 != NULL){
        memcpy($input.array, $1, $input.cap);
    }
}
%typemap(freearg) (void *inbuf, int len){
    if($1 != NULL){
        free($1);
    }
}

%typemap(gotype) (const void *VOIDBUF, int len) %{[]byte%}
%typemap(in) (const void *VOIDBUF, int len) {
    $1=$input.array;
    $2=$input.len;
}

#define STACK_OF(type) struct stack_st_## type