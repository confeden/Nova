// Plasma: a dive into ionised gas. Fuzzy neon filaments (soft arcs along the contours of domain-warped, time-advected noise) with
// bright hot cores, thin veils between them, colours cycling through the palette and hue-shifted mixes in time and space.
// High emission, low density: the radiance cascades spread the bloom. Three Hann-crossfaded zoom layers (absolute index A), no restarts.
vec3 hrot(vec3 c,float a){float cs=cos(a),sn=sin(a);float k=.3333333,q=.5773503;
 float m0=cs+(1.-cs)*k,m1=k*(1.-cs)-q*sn,m2=k*(1.-cs)+q*sn;
 return max(vec3(c.x*m0+c.y*m1+c.z*m2,c.x*m2+c.y*m0+c.z*m1,c.x*m1+c.y*m2+c.z*m0),0.);}
vec3 satc(vec3 c,float s){return max(mix(vec3(dot(c,vec3(.3,.55,.15))),c,s),0.);}
float fb3(vec2 p){float a=.5,s=0.;for(int i=0;i<3;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.143;}
float fb4(vec2 p){float a=.5,s=0.;for(int i=0;i<4;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.067;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tm=t*.7;float tt=t*.045;float N=floor(tt);float fz=tt-N;
 vec3 em=vec3(0),vl=vec3(0);float W=0.,veil=0.;
 for(int k=0;k<3;k++){
  float fk=float(k);float e=fk-fz;float A=fk+N;float f=1.15*exp2(e*1.15);
  float x=clamp((e+1.)/3.,0.,1.);float wh=.5-.5*cos(6.2832*x);
  vec2 q=rot(A*.8)*p*f+vec2(A*11.3,A*5.7)+S;
  vec2 tv=vec2(tm*.09,-tm*.07);
  vec2 w1=vec2(fb3(q*.8+tv+3.),fb3(q*.8-tv.yx+11.))-.5;
  vec2 q2=q+1.6*w1;
  vec2 w2=vec2(fb3(q2*1.7+vec2(-tm*.14,tm*.11)+7.),fb3(q2*1.7+vec2(tm*.12,tm*.15)+17.))-.5;
  vec2 q3=q2+.8*w2;
  float f1=fb4(q3+vec2(0.,tm*.05)),f2=fb4(q3*1.8+vec2(5.-tm*.06,tm*.08));
  float s=.011+.045*vn(q*.9+tv*1.3);                 // line softness: thin arcs here, wide fuzzy glows there
  float L1=pow(s/(abs(f1-.47)+s),2.8),L2=pow(s*.7/(abs(f2-.5)+s*.7),3.6);
  float act=.03+.97*smoothstep(.42,.62,fb3(q3*.45+A*2.+7.));   // arcs gather in active regions, calm dark gaps between
  float br=.25+1.5*pow(fb3(q3*2.2+vec2(tm*.2,-tm*.15)),3.)*3.;    // beads of brightness running along the arcs
  float ph=t*.045+A*.37+1.1*w1.x+.7*f1;
  vec3 c1=satc(mix(pal(ph),hrot(uA,6.2832*ph),.6),1.9),c2=satc(mix(pal(ph+.4+.5*f2),hrot(uC,6.2832*(ph+.45+.5*f2)),.6),1.9);
  vec3 a1=mix(c1,vec3(1.),pow(L1,5.)*.65)*L1,a2=mix(c2,vec3(1.),pow(L2,5.)*.6)*L2;
  float vv=smoothstep(.38,.8,fb3(rot(1.)*q*vec2(.6,1.7)+w1*1.8+vec2(0.,tm*.06)));
  vec3 c3=satc(pal(ph+.66),1.6);
  em+=wh*act*(a1*br*1.5+a2*(.12+br*.35));
  vl+=wh*c3*vv*vv*vv*vv*.06;veil+=wh*vv;W+=wh;
 }
 W=max(W,1e-3);em/=W;vl/=W;veil/=W;
 emi=em*4.+vl;
 alb=vec3(.01,.012,.02)+vl*.3;den=.25+veil*.9;h=veil*.1;
}
