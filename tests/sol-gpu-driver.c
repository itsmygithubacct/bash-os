/* SPDX-License-Identifier: MIT */
/* Explicit GBM/EGL/GLES ABI fixture. This is a strict host memory model, not a
   hardware driver or a GLSL interpreter. Known copy/half/gradient shader inputs
   have independent Python pixel oracles. gpu's actual dlopen, initialization,
   upload, draw, readback and SCM_RIGHTS paths execute without modification. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct buffer { int fd, w, h, stride; unsigned char *data; };
static struct buffer *bo;
static unsigned next_id = 1, bound, attached, current, error;
static char *sources[4096];
static unsigned programs[4096], modes[4096];
static unsigned char *input;
static int iw, ih;
static float tick;
static uint64_t uploads, reads, draws, upload_bytes, read_bytes, allocations, buffer_peak;
__attribute__((destructor)) static void trace(void) {
    assert(!bo && !input);
    for(unsigned i=1;i<next_id;i++)assert(!sources[i] && !programs[i]);
    const char *path=getenv("GPU_FIXTURE_TRACE");
    if (!path) return;
    FILE *file=fopen(path,"a"); assert(file);
    fprintf(file,"{\"uploads\":%" PRIu64 ",\"readbacks\":%" PRIu64
            ",\"draws\":%" PRIu64 ",\"upload_bytes\":%" PRIu64
            ",\"readback_bytes\":%" PRIu64 ",\"allocations\":%" PRIu64
            ",\"buffer_bytes_peak\":%" PRIu64 "}\n",
            uploads,reads,draws,upload_bytes,read_bytes,allocations,buffer_peak);
    assert(!fclose(file));
}
static int fail(const char *stage) { const char *v=getenv("GPU_FIXTURE_FAIL"); return v && !strcmp(v,stage); }
static unsigned id(void) { assert(next_id < 4096); return next_id++; }
void *gbm_create_device(int fd) {
    assert(fcntl(fd,F_GETFD)>=0);
    if (fail("device")) return NULL;
    return malloc(1);
}
void gbm_device_destroy(void *d) { free(d); }
void *gbm_bo_create(void *d, uint32_t w, uint32_t h, uint32_t format, uint32_t flags) {
    assert(d && format==0x34325258 && flags==20 && !bo);
    if (fail("buffer")) return NULL;
    bo=calloc(1,sizeof(*bo)); assert(bo);
    bo->w=(int)w;bo->h=(int)h;bo->stride=(int)w*4+16; /* Exercise padded export rows. */
    bo->fd=memfd_create("sol-gpu-fixture",MFD_CLOEXEC); assert(bo->fd>=0);
    assert(!ftruncate(bo->fd,(off_t)bo->stride*h+64));
    bo->data=mmap(NULL,(size_t)bo->stride*h+64,PROT_READ|PROT_WRITE,MAP_SHARED,bo->fd,0);
    assert(bo->data!=MAP_FAILED);
    allocations++;uint64_t size=(uint64_t)bo->stride*h+64;
    if(size>buffer_peak)buffer_peak=size;
    return bo;
}
void gbm_bo_destroy(void *b) {
    assert(b==bo); munmap(bo->data,(size_t)bo->stride*bo->h+64);close(bo->fd);free(bo);bo=NULL;
    free(input);input=NULL;iw=ih=0;
}
int gbm_bo_get_fd(void *b) { assert(b==bo); return fail("export") ? -1 : fcntl(bo->fd,F_DUPFD_CLOEXEC,0); }
uint32_t gbm_bo_get_stride(void *b) { assert(b==bo); return (uint32_t)bo->stride; }
uint32_t gbm_bo_get_offset(void *b,int plane) { assert(b==bo && !plane);return 64; }
uint64_t gbm_bo_get_modifier(void *b) { assert(b==bo);return 0; }
void *eglGetDisplay(void *d) { return d; }
void *eglGetPlatformDisplayEXT(unsigned platform, void *d,const int *attrs) { assert(platform==0x31d7 && !attrs);return d; }
unsigned eglInitialize(void *d,int *major,int *minor) { assert(d && !major && !minor);return !fail("initialize"); }
unsigned eglBindAPI(unsigned api) { assert(api==0x30a0);return 1; }
unsigned eglChooseConfig(void *d,const int *a,void **c,int size,int *count) {
    assert(d && a[0]==0x3040 && a[1]==4 && a[2]==0x3033 && a[3]==0 && a[4]==0x3038 && size==1);
    *c=d;*count=1;return 1;
}
void *eglCreateContext(void *d,void *c,void *share,const int *a) {
    assert(d==c && !share && a[0]==0x3098 && a[1]==2 && a[2]==0x3038);
    return fail("context") ? NULL : malloc(1);
}
unsigned eglMakeCurrent(void *d,void *draw,void *read,void *context) { assert(d && !draw && !read);(void)context;return 1; }
unsigned eglDestroyContext(void *d,void *c) { assert(d);free(c);return 1; }
unsigned eglTerminate(void *d) { assert(d);return 1; }
void *eglCreateImageKHR(void *d,void *context,unsigned target,void *client,const int *a) {
    assert(d && !context && target==0x3270 && !client);
    assert(a[0]==0x3057 && a[1]==bo->w && a[2]==0x3056 && a[3]==bo->h);
    assert(a[4]==0x3271 && a[5]==0x34325258 && a[6]==0x3272 && fcntl(a[7],F_GETFD)>=0);
    assert(a[8]==0x3273 && a[9]==64 && a[10]==0x3274 && a[11]==bo->stride && a[12]==0x3038);
    return fail("image") ? NULL : bo;
}
unsigned eglDestroyImageKHR(void *d,void *image) { assert(d && image==bo);return 1; }
void glEGLImageTargetTexture2DOES(unsigned target,void *image) { assert(target==0xde1 && image==bo);attached=bound; }
void glGenTextures(int n,unsigned *out) { assert(n==1);*out=id(); }
void glDeleteTextures(int n,const unsigned *values) { assert(n==1 && *values); }
void glBindTexture(unsigned t,unsigned value) { assert(t==0xde1);bound=value; }
void glTexParameteri(unsigned t,unsigned p,int value) { assert(t==0xde1 && p>=0x2800 && p<=0x2803);assert(value==0x2600 || value==0x812f); }
void glTexImage2D(unsigned t,int level,int internal,int w,int h,int border,unsigned format,unsigned type,const void *pixels) {
    assert(t==0xde1 && !level && internal==0x1908 && !border && format==0x1908 && type==0x1401 && bound!=attached);
    assert(w==bo->w && h==bo->h && pixels);iw=w;ih=h;
    uploads++;upload_bytes+=(uint64_t)w*h*4;
    free(input);input=malloc((size_t)w*h*4);assert(input);memcpy(input,pixels,(size_t)w*h*4);
}
void glGenFramebuffers(int n,unsigned *out) { assert(n==1);*out=id(); }
void glDeleteFramebuffers(int n,const unsigned *values) { assert(n==1 && *values); }
void glBindFramebuffer(unsigned target,unsigned value) { assert(target==0x8d40 && value); }
void glFramebufferTexture2D(unsigned t,unsigned attachment,unsigned target,unsigned texture,int level) {
    assert(t==0x8d40 && attachment==0x8ce0 && target==0xde1 && texture==attached && !level);
}
unsigned glCheckFramebufferStatus(unsigned target) { assert(target==0x8d40);return fail("framebuffer") ? 0 : 0x8cd5; }
unsigned glCreateShader(unsigned type) { assert(type==0x8b30 || type==0x8b31);return id(); }
void glShaderSource(unsigned shader,int n,const char *const *text,const int *lengths) { assert(n==1 && !lengths);sources[shader]=strdup(*text);assert(sources[shader]); }
void glCompileShader(unsigned shader) { assert(sources[shader]); }
void glGetShaderiv(unsigned shader,unsigned name,int *ok) {
    assert(name==0x8b81);
    const char *source=sources[shader];
    *ok=!strstr(source,"INVALID") && (strstr(source,"gl_Position") ||
         strstr(source,"texture2D(canvas,uv)") || strstr(source,"uv.x,uv.y,time") || strstr(source,"LINK_FAIL"));
}
void glGetShaderInfoLog(unsigned shader,int size,int *length,char *out) { (void)shader;snprintf(out,(size_t)size,"fixture compile failure");if(length)*length=(int)strlen(out); }
void glDeleteShader(unsigned shader) { free(sources[shader]);sources[shader]=NULL; }
unsigned glCreateProgram(void) { return id(); }
void glAttachShader(unsigned program,unsigned shader) {
    assert(sources[shader]);
    if(strstr(sources[shader],"gl_FragColor")) {
        programs[program]=strstr(sources[shader],"LINK_FAIL") ? 0 : 1;
        modes[program]=strstr(sources[shader],"uv.x,uv.y,time") ? 1 : strstr(sources[shader],"*0.5") ? 2 : 0;
    }
}
void glBindAttribLocation(unsigned program,unsigned index,const char *name) { assert(program && !index && !strcmp(name,"position")); }
void glLinkProgram(unsigned program) { assert(program); }
void glGetProgramiv(unsigned program,unsigned name,int *ok) { assert(name==0x8b82);*ok=(int)programs[program]; }
void glGetProgramInfoLog(unsigned program,int size,int *length,char *out) { (void)program;snprintf(out,(size_t)size,"fixture link failure");if(length)*length=(int)strlen(out); }
void glDeleteProgram(unsigned program) { programs[program]=modes[program]=0; }
void glUseProgram(unsigned program) { assert(programs[program]);current=program; }
int glGetUniformLocation(unsigned program,const char *name) { assert(program==current);return !strcmp(name,"canvas") ? 1 : !strcmp(name,"time") ? 2 : 3; }
void glUniform1f(int location,float value) { assert(location==2);tick=value; }
void glUniform2f(int location,float w,float h) { assert(location==3 && w==bo->w && h==bo->h); }
void glUniform1i(int location,int value) { assert(location==1 && !value); }
void glViewport(int x,int y,int w,int h) { assert(!x && !y && w==bo->w && h==bo->h); }
void glActiveTexture(unsigned texture) { assert(texture==0x84c0); }
void glEnableVertexAttribArray(unsigned index) { assert(!index); }
void glVertexAttribPointer(unsigned index,int n,unsigned type,unsigned char norm,int stride,const void *ptr) {
    assert(!index && n==2 && type==0x1406 && !norm && !stride);
    const float wanted[]={-1,-1,1,-1,-1,1,1,1};assert(!memcmp(ptr,wanted,sizeof(wanted)));
}
void glDrawArrays(unsigned kind,int first,int count) {
    assert(kind==5 && !first && count==4 && input && iw==bo->w && ih==bo->h);
    if(fail("draw")) { error=0x502;return; }
    draws++;
    for(int y=0;y<bo->h;y++)for(int x=0;x<bo->w;x++) {
        unsigned char *out=bo->data+64+(size_t)y*bo->stride+x*4;
        const unsigned char *in=input+((size_t)(bo->h-1-y)*iw+x)*4;
        if(modes[current]==1) {
            out[2]=(unsigned char)lround((x+.5)/bo->w*255);
            out[1]=(unsigned char)lround((bo->h-y-.5)/bo->h*255);
            out[0]=(unsigned char)lround(tick*255);
        } else for(int c=0;c<3;c++)out[2-c]=(unsigned char)lround(in[c]*(modes[current]==2 ? .5 : 1));
        out[3]=255;
    }
}
void glReadPixels(int x,int y,int w,int h,unsigned format,unsigned type,void *pixels) {
    assert(!x && !y && w==bo->w && h==bo->h && format==0x1908 && type==0x1401);
    if(fail("read")){error=0x502;return;}
    reads++;read_bytes+=(uint64_t)w*h*4;
    unsigned char *out=pixels;
    for(int row=0;row<h;row++)for(int col=0;col<w;col++) {
        const unsigned char *p=bo->data+64+(size_t)row*bo->stride+col*4;
        *out++=p[2];*out++=p[1];*out++=p[0];*out++=255;
    }
}
void glFinish(void) { }
unsigned glGetError(void) { unsigned result=error;error=0;return result; }
const unsigned char *glGetString(unsigned name) { assert(name==0x1f01);return (const unsigned char *)"sol-gpu ABI fixture (host memory; no hardware)"; }
void *eglGetProcAddress(const char *name) {
#define PROC(f) if(!strcmp(name,#f)) return (void *)f
    PROC(eglGetPlatformDisplayEXT);PROC(eglCreateImageKHR);PROC(eglDestroyImageKHR);PROC(glEGLImageTargetTexture2DOES);
#undef PROC
    return NULL;
}
