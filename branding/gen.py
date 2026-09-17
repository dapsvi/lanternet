#!/usr/bin/env python3
import os

OUT = os.path.dirname(os.path.abspath(__file__))
BLUE = "#0B57D0"

BODY = ("M 316,426 A 196,160 0 0 1 708,426 L 656,731 L 684,731 L 684,781 "
        "Q 684,801 664,801 L 360,801 Q 340,801 340,781 L 340,731 L 368,731 Z")

A1 = "M 446.2,593.2 A 93,93 0 0 1 577.8,593.2"
A2 = "M 396,543 A 164,164 0 0 1 628,543"

SIGNAL = [A1, A2]
KNOB = '<circle cx="512" cy="253" r="30"/>'
DOT = '<circle cx="512" cy="659" r="32"/>'


def head(title):
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" '
            'viewBox="0 0 1024 1024"><title>%s</title>\n' % title)


def body_path(d=BODY):
    return '<path d="%s"/>' % d


def knockout(name, color, holes, sw=38, dot=True, knob=True):
    s = head("lanternet mark")
    s += '<defs><mask id="cut" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024">'
    s += '<rect x="0" y="0" width="1024" height="1024" fill="#fff"/>'
    s += '<g fill="#000" stroke="#000" stroke-width="%d" stroke-linecap="butt">' % sw
    s += ''.join('<path d="%s" fill="none"/>' % a for a in holes)
    if dot:
        s += DOT
    s += '</g></mask></defs>\n'
    s += '<g fill="%s" mask="url(#cut)">' % color
    s += body_path()
    if knob:
        s += KNOB
    s += '</g>\n</svg>\n'
    open(os.path.join(OUT, name), "w").write(s)


def outline(name, color, holes, sw=34, dot_r=17):
    s = head("lanternet mark outline")
    s += '<g fill="none" stroke="%s" stroke-width="34" stroke-linejoin="round">' % color
    s += body_path()
    s += '<circle cx="512" cy="253" r="30"/></g>\n'
    s += '<g fill="%s" stroke="%s" stroke-width="%d" stroke-linecap="butt">' % (color, color, sw)
    s += ''.join('<path d="%s" fill="none"/>' % a for a in holes)
    s += '<circle cx="512" cy="659" r="%d"/></g>\n' % dot_r
    s += '</svg>\n'
    open(os.path.join(OUT, name), "w").write(s)


def solid(name, color):
    s = head("lanternet mark solid")
    s += '<g fill="%s">' % color
    s += body_path()
    s += '<circle cx="512" cy="253" r="30"/>'
    s += '</g>\n</svg>\n'
    open(os.path.join(OUT, name), "w").write(s)


knockout("lanternet-mark.svg", BLUE, SIGNAL)
knockout("lanternet-mark-white.svg", "#FFFFFF", SIGNAL)
outline("lanternet-mark-outline.svg", BLUE, SIGNAL)
solid("lanternet-mark-solid.svg", BLUE)
print("written")
