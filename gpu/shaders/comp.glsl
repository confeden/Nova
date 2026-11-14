#version 300 es
precision highp float;
uniform sampler2D uS0,uS1,uCas;uniform vec2 uRes,uSz;uniform vec3 uBg0,uBg1,uBg2;uniform float uInt;uniform float uSatD;
out vec4 o;
float h21(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
void main(){vec2 uv=gl_FragCoord.xy/uRes;
 vec4 s0=texture(uS0,uv),s1=texture(uS1,uv);
 vec2 tile=uSz*.5;vec2 u=clamp(uv*tile,vec2(.5),tile-.5);vec3 F=vec3(0);
 for(int k=0;k<4;k++){vec2 tj=vec2(float(k&1),float(k>>1));F+=texture(uCas,(tj*tile+u)/uSz).rgb;}F*=.25;F/=1.+.4*max(F.r,max(F.g,F.b));
 vec2 e=1.5/uRes;
 float hx=texture(uS1,uv+vec2(e.x,0.)).a-texture(uS1,uv-vec2(e.x,0.)).a;
 float hy=texture(uS1,uv+vec2(0.,e.y)).a-texture(uS1,uv-vec2(0.,e.y)).a;
 float relief=clamp(1.+dot(vec2(hx,hy)*uRes.y*.012,vec2(.55,-.75)),.45,1.7);
 vec3 t=s1.rgb*(.16+F)*relief+s0.rgb*.5+F*.10;
 float y=1.-uv.y;vec3 base=mix(mix(uBg0,uBg1,smoothstep(0.,.5,y)),uBg2,smoothstep(.5,1.,y));
 vec3 c=base*(1.-uInt*.6)+t*uInt;
 c=vec3(dot(c,vec3(.299,.587,.114)))*(-uSatD)+c*(1.+uSatD);
 float m=max(c.r,max(c.g,c.b));c*=(1.-exp(-m*1.25))/max(m,1e-4);c=mix(c,vec3(1.),smoothstep(2.5,9.,m)*.45);
 c=pow(clamp(c,0.,1.),vec3(1./2.2));c+=(h21(gl_FragCoord.xy)-.5)/255.;o=vec4(c,1.);}