/* Verify the active X desktop uses a hardware-accelerated Intel Mesa context.
 * cc -Wall -Wextra intel-glx-renderer.c -o intel-glx-renderer -lGL -lX11
 * Run inside the desktop session. Exit 0 for Intel hardware, 1 for another
 * renderer, or 2 if the context, pixel readback or Mesa query failed.
 */
#include <GL/gl.h>
#include <GL/glx.h>
#include <GL/glxext.h>
#include <X11/Xlib.h>
#include <stdio.h>

int main(void)
{
    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fputs("Cannot open the X display\n", stderr);
        return 2;
    }
    int attrs[] = {
        GLX_DRAWABLE_TYPE, GLX_PBUFFER_BIT, GLX_RENDER_TYPE, GLX_RGBA_BIT,
        GLX_RED_SIZE, 8, GLX_GREEN_SIZE, 8, GLX_BLUE_SIZE, 8,
        GLX_DOUBLEBUFFER, False, None
    };
    int count = 0;
    GLXFBConfig *configs = glXChooseFBConfig(display, DefaultScreen(display), attrs, &count);
    GLXContext context = NULL;
    GLXPbuffer surface = None;
    int result = 2;
    if (configs && count > 0) {
        int size[] = { GLX_PBUFFER_WIDTH, 1, GLX_PBUFFER_HEIGHT, 1, None };
        context = glXCreateNewContext(display, configs[0], GLX_RGBA_TYPE, NULL, True);
        surface = glXCreatePbuffer(display, configs[0], size);
    }
    if (!context || !surface || !glXMakeContextCurrent(display, surface, surface, context)) {
        fputs("Cannot create a GLX context on the X display\n", stderr);
        goto done;
    }
    printf("OpenGL renderer: %s\n", (const char *)glGetString(GL_RENDERER));
    glClearColor(1.0f, 0.0f, 1.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    GLubyte pixel[4] = { 0 };
    glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
    if (glGetError() != GL_NO_ERROR || pixel[0] != 255 || pixel[1] || pixel[2] != 255) {
        fputs("GLX pixel readback failed\n", stderr);
        goto done;
    }
    PFNGLXQUERYCURRENTRENDERERINTEGERMESAPROC query =
        (PFNGLXQUERYCURRENTRENDERERINTEGERMESAPROC)
        glXGetProcAddressARB((const GLubyte *)"glXQueryCurrentRendererIntegerMESA");
    unsigned accelerated = 0, vendor = 0;
    if (!query || !query(GLX_RENDERER_ACCELERATED_MESA, &accelerated)
            || !query(GLX_RENDERER_VENDOR_ID_MESA, &vendor)) {
        fputs("Mesa renderer query unavailable\n", stderr);
        goto done;
    }
    Bool direct = glXIsDirect(display, context);
    printf("Direct: %s, accelerated: %s, PCI vendor: 0x%x\n",
           direct ? "yes" : "no", accelerated ? "yes" : "no", vendor);
    result = direct && accelerated && vendor == 0x8086 ? 0 : 1;
done:
    if (context) {
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
    }
    if (surface)
        glXDestroyPbuffer(display, surface);
    if (configs)
        XFree(configs);
    XCloseDisplay(display);
    return result;
}
