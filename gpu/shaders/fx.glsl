#version 330 core
// Native-only passes over the composited frame (uBlur = copy of it, RGBA8, full mip chain).
//  uMode 0, no blending: frosted glass. Writes the blurred+grained frame only where the glass mask
//         is > 0 (discard elsewhere), so mask-0 pixels stay exactly what the composite gave.
//  uMode 1, additive blending: hover halo on the texture + shimmer inside the glass plate.
//         Adds nothing at all when uHot is 0. Includes a crisp 1.5 px outline just outside the plate.
uniform sampler2D uBlur,uOv,uMask;
uniform vec2 uRes;
uniform int uMode,uHasOv,uHasMask;
uniform vec4 uRect;       // l,t,r,b in frame px, top-down
uniform vec3 uCol;        // halo colour, display space 0..1
uniform float uHot,uTime,uReach,uHue,uRadius;
out vec4 o;
float h21(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
float vn(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);
 return mix(mix(h21(i),h21(i+vec2(1.,0.)),f.x),mix(h21(i+vec2(0.,1.)),h21(i+vec2(1.,1.)),f.x),f.y);}
vec3 hsl2rgb(vec3 c){vec3 k=mod(vec3(0.,8.,4.)+c.x*12.,12.);return c.z-c.y*min(c.z,1.-c.z)*clamp(min(k-3.,9.-k),-1.,1.);}
void main(){
 ivec2 p=ivec2(gl_FragCoord.xy);
 int H=int(uRes.y+.5);
 ivec2 tp=ivec2(p.x,H-1-p.y);
 vec2 uv=gl_FragCoord.xy/uRes;
 float m=0.;
 if(uHasMask!=0)m=texelFetch(uMask,tp,0).r;
 if(uMode==0){
  if(m<=0.)discard;
  // Fogged glass: a soft blur of the frame whose strength varies in patches (condensation), a faint
  // whitening where it is foggiest and a very fine matte grain. Static: no per-frame cost. (No droplets: the
  // bright 2 px specks made the glass look dirty.)
  vec2 s=5./uRes;vec3 f=vec3(0.);
  for(int j=-1;j<=1;j++)for(int i=-1;i<=1;i++){
   float w=(i==0?2.:1.)*(j==0?2.:1.);
   f+=w*textureLod(uBlur,uv+vec2(float(i),float(j))*s,1.9).rgb;
  }
  f/=16.;
  vec2 fc=gl_FragCoord.xy;
  float n=.6*vn(fc/22.)+.4*vn(fc/7.+17.);
  float fog=clamp(.45+.75*n,0.,1.);
  vec3 sharp=texelFetch(uBlur,p,0).rgb;
  vec3 g=mix(sharp,f,fog)+fog*.028;
  g+=(h21(fc)-.5)*(4./255.);
  o=vec4(mix(sharp,g,m),1.);
  return;
 }
 float ova=0.;
 if(uHasOv!=0)ova=texelFetch(uOv,tp,0).a;
 vec2 q=vec2(gl_FragCoord.x,uRes.y-gl_FragCoord.y);
 vec2 c0=.5*(uRect.xy+uRect.zw),hs=.5*(uRect.zw-uRect.xy);
 float rad=min(uRadius,min(hs.x,hs.y));
 vec2 dq=abs(q-c0)-hs+rad;
 float d=length(max(dq,0.))+min(max(dq.x,dq.y),0.)-rad;
 // light falling on the texture: rim glow outside (reach) and a short one inside, no hard edge
 float luma=dot(textureLod(uBlur,uv,3.).rgb,vec3(.299,.587,.114));
 float fall=d>=0.?exp(-d/uReach)*smoothstep(0.,1.5,d):0.;   // outside the plate only
 fall*=1.-smoothstep(1.2*uReach,3.*uReach,max(d,0.));
 float shield=1.-.35*max(m,ova);
 vec3 c=uCol*(.85*uHot*fall*(.55+.9*luma))*shield;
 // crisp outline: a ~1.5 px line just outside the plate edge (centre d=+1 px), not softened by the
 // glass shield and not scaled by the picture; nothing at d<0
 float rd=d-.7;
 float ring=exp(-rd*rd/(2.*.8*.8))*smoothstep(-.45,.3,d);
 c+=mix(uCol,vec3(1.),.35)*(ring*uHot*.9);
 if(d<0.&&m>0.){
  // iridescent sweep inside the plate + a thin bright rim
  float inside=clamp(.5-d,0.,1.);
  float band=.5+.5*sin(dot(q,vec2(.8,.6))*.035-uTime*1.6);
  vec3 sc=hsl2rgb(vec3(uHue+.06*(2.*band-1.),.8,.62));
  c+=sc*(uHot*.14*band*m*inside);
  c+=mix(uCol,vec3(1.),.5)*(exp(-abs(d)*1.2)*.07*uHot*m);
 }
 o=vec4(c,0.);
}
