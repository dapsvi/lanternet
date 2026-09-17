#!/usr/bin/env python3
import math, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.abspath(os.path.join(HERE, "..", "android", "app", "src", "main"))
RES = os.path.join(APP, "res")
BLUE = "#FF0B57D0"
sys.path.insert(0, HERE)
import gen

D = 45.0
ARCS = [(93, 38), (164, 38)]
DOT_C = (512, 659)
DOT_R = 32
KNOB_C = (512, 253)
KNOB_R = 30
LEGACY = [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]
MARK_FILL = 0.62
VEC_SCALE = 0.75


def pt(cx, cy, r, a):
    return cx + r * math.sin(a), cy - r * math.cos(a)


def band(cx, cy, r, w, deg=D):
    ro, ri = r + w / 2.0, r - w / 2.0
    a = math.radians(deg)
    x1, y1 = pt(cx, cy, ro, -a)
    x2, y2 = pt(cx, cy, ro, a)
    x3, y3 = pt(cx, cy, ri, a)
    x4, y4 = pt(cx, cy, ri, -a)
    return ("M %.1f,%.1f A %.1f,%.1f 0 0 1 %.1f,%.1f L %.1f,%.1f "
            "A %.1f,%.1f 0 0 0 %.1f,%.1f Z" %
            (x1, y1, ro, ro, x2, y2, x3, y3, ri, ri, x4, y4))


def circle(cx, cy, r):
    return ("M %.1f,%.1f A %.1f,%.1f 0 1 1 %.1f,%.1f A %.1f,%.1f 0 1 1 %.1f,%.1f Z" %
            (cx - r, cy, r, r, cx + r, cy, r, r, cx - r, cy))


VEC_HEAD = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
            '    android:width="108dp"\n    android:height="108dp"\n'
            '    android:viewportWidth="1024"\n    android:viewportHeight="1024">\n')


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    print("wrote", os.path.relpath(path, APP))


def foreground():
    holes = " ".join(band(*DOT_C, r, w) for r, w in ARCS) + " " + circle(*DOT_C, DOT_R)
    s = VEC_HEAD
    s += ('    <group android:scaleX="%.2f" android:scaleY="%.2f"\n'
          '        android:pivotX="512" android:pivotY="512">\n' % (VEC_SCALE, VEC_SCALE))
    s += ('        <path\n            android:fillColor="#FFFFFFFF"\n'
          '            android:fillType="evenOdd"\n            android:pathData="%s %s" />\n'
          % (gen.BODY, holes))
    s += ('        <path\n            android:fillColor="#FFFFFFFF"\n'
          '            android:pathData="%s" />\n' % circle(*KNOB_C, KNOB_R))
    s += '    </group>\n'
    s += "</vector>\n"
    write(os.path.join(RES, "drawable", "ic_launcher_foreground.xml"), s)


def monochrome():
    s = VEC_HEAD
    s += ('    <group android:scaleX="%.2f" android:scaleY="%.2f"\n'
          '        android:pivotX="512" android:pivotY="512">\n' % (VEC_SCALE, VEC_SCALE))
    s += ('        <path\n            android:fillColor="#FFFFFFFF"\n'
          '            android:pathData="%s" />\n' % gen.BODY)
    s += ('        <path\n            android:fillColor="#FFFFFFFF"\n'
          '            android:pathData="%s" />\n' % circle(*KNOB_C, KNOB_R))
    s += '    </group>\n'
    s += "</vector>\n"
    write(os.path.join(RES, "drawable", "ic_launcher_monochrome.xml"), s)


def adaptive():
    for name in ("ic_launcher.xml", "ic_launcher_round.xml"):
        s = ('<?xml version="1.0" encoding="utf-8"?>\n'
             '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
             '    <background android:drawable="@color/ic_launcher_background" />\n'
             '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
             '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n'
             '</adaptive-icon>\n')
        write(os.path.join(RES, "mipmap-anydpi-v26", name), s)


def colors():
    p = os.path.join(RES, "values", "colors.xml")
    s = open(p).read()
    if "ic_launcher_background" not in s:
        s = s.replace("</resources>",
                      '    <color name="ic_launcher_background">%s</color>\n</resources>' % BLUE)
        write(p, s)


def legacy():
    white = os.path.join(HERE, "lanternet-mark-white.svg")
    for dens, size in LEGACY:
        d = os.path.join(RES, "mipmap-" + dens)
        os.makedirs(d, exist_ok=True)
        ms = int(round(size * MARK_FILL / 0.56))
        tmp = "/tmp/lt_icon_%d.png" % size
        subprocess.run(["rsvg-convert", "-w", str(ms), "-h", str(ms), white, "-o", tmp], check=True)
        r = int(round(size * 0.22))
        subprocess.run(["magick", "-size", "%dx%d" % (size, size), "xc:none", "-fill", "#0B57D0",
                        "-draw", "roundrectangle 0,0 %d,%d %d,%d" % (size - 1, size - 1, r, r),
                        tmp, "-gravity", "center", "-composite",
                        "-define", "webp:lossless=true",
                        os.path.join(d, "ic_launcher.webp")], check=True)
        subprocess.run(["magick", "-size", "%dx%d" % (size, size), "xc:none", "-fill", "#0B57D0",
                        "-draw", "circle %d,%d %d,%d" % (size / 2, size / 2, size / 2, size / 2),
                        tmp, "-gravity", "center", "-composite",
                        "-define", "webp:lossless=true",
                        os.path.join(d, "ic_launcher_round.webp")], check=True)
        print("wrote mipmap-%s/ic_launcher(|_round).webp" % dens)


foreground()
monochrome()
adaptive()
colors()
legacy()
old = os.path.join(RES, "drawable", "ic_launcher_background.xml")
if os.path.exists(old):
    os.remove(old)
    print("removed drawable/ic_launcher_background.xml")
