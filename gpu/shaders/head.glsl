#version 300 es
precision highp float;
uniform vec2 uRes,uVel;uniform float uT,uSeed,uGain;uniform vec3 uA,uB,uC,uBg,uPtr;uniform sampler2D uAtlas;
layout(location=0) out vec4 o0;layout(location=1) out vec4 o1;
#define S vec2(mod(uSeed*17.3,97.),mod(uSeed*9.1,89.))   // bounded: a big offset costs float precision (fine moirÃ© in water, broken blobs in ether at variant 428)
float h21(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
vec2 h22(vec2 p){float n=h21(p);return vec2(n,h21(p+n+17.1));}
float vn(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h21(i),h21(i+vec2(1,0)),f.x),mix(h21(i+vec2(0,1)),h21(i+vec2(1,1)),f.x),f.y);}
float fbm(vec2 p){float a=.5,s=0.;for(int i=0;i<6;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s;}
mat2 rot(float a){float c=cos(a),s=sin(a);return mat2(c,-s,s,c);}
vec3 pal(float t){t=fract(t)*3.;float f=smoothstep(0.,1.,fract(t));return t<1.?mix(uA,uB,f):t<2.?mix(uB,uC,f):mix(uC,uA,f);}
vec3 voro(vec2 p){vec2 i=floor(p),f=fract(p);float d1=8.,d2=8.;vec2 id=vec2(0);
 for(int y=-1;y<=1;y++)for(int x=-1;x<=1;x++){vec2 g=vec2(float(x),float(y));vec2 r=g+h22(i+g)-f;float d=dot(r,r);if(d<d1){d2=d1;d1=d;id=i+g;}else if(d<d2)d2=d;}
 return vec3(sqrt(d1),sqrt(d2)-sqrt(d1),h21(id+3.7));}
