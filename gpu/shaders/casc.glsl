#version 300 es
precision highp float;
uniform sampler2D uScene,uUp;uniform vec2 uSz;uniform int uC,uN;uniform float uLod,uL,uGE;
out vec4 o;
void main(){
 float sq=float(2<<uC);vec2 tile=uSz/sq;vec2 fc=gl_FragCoord.xy;
 vec2 ti=floor(fc/tile);vec2 pp=fc-ti*tile;
 float idx=ti.x+ti.y*sq;float ang=6.2831853*(idx+.5)/(sq*sq);vec2 dir=vec2(cos(ang),sin(ang));
 vec2 org=pp*sq;
 float s0=uC==0?0.:float(1<<(2*uC));float s1=float(1<<(2*(uC+1)));float st=float(1<<uC);
 int n=int((s1-s0)/st+.5);float lod=float(uC)+uLod;float ds=st*uL/uSz.y;
 vec3 rad=vec3(0);float T=1.;
 for(int i=0;i<n;i++){vec2 q=(org+dir*uL*(s0+(float(i)+.5)*st))/uSz;
  if(q.x<0.||q.y<0.||q.x>1.||q.y>1.){T=0.;break;}
  vec4 s=textureLod(uScene,q,lod);rad+=T*s.rgb*ds*uGE;T*=exp(-s.a*ds);if(T<.004){T=0.;break;}}
 if(uC<uN-1&&T>0.){float sq2=sq*2.;vec2 tile2=uSz/sq2;vec2 u=clamp(pp*.5,vec2(.5),tile2-.5);vec3 acc=vec3(0);
  for(int k=0;k<4;k++){float j=idx*4.+float(k);vec2 tj=vec2(mod(j,sq2),floor(j/sq2));acc+=texture(uUp,(tj*tile2+u)/uSz).rgb;}
  rad+=T*acc*.25;}
 o=vec4(rad,T);}