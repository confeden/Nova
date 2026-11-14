
vec2 warp(vec2 p){vec2 d=p-uPtr.xy;float w=exp(-dot(d,d)*26.)*uPtr.z;float a=.5*w*w;
 d=mat2(cos(a),-sin(a),sin(a),cos(a))*d;return uPtr.xy+d*(1.-.34*w)-uVel*w*1.4;}
void main(){vec2 p=warp((gl_FragCoord.xy-.5*uRes)/uRes.y);vec3 alb=vec3(0),emi=vec3(0);float den=0.,h=0.;
 tex(p,uT,alb,emi,den,h);
 o0=vec4(max(emi,0.)*uGain,max(den,0.));o1=vec4(clamp(alb,0.,4.),clamp(h,0.,1.));}