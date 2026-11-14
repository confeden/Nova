// Space: real nebulae (emission = hot hue with bright cores + filaments, reflection = cool hue, dark dust silhouettes with bright rims,
// deep-space gaps), plus four parallax star layers (faint dense, mid with halos, near with spikes) and rare galaxies.
// Every layer is an endless zoom cycle (absolute index A, Hann or in/out fades), no restarts.
vec3 hrot(vec3 c,float a){float cs=cos(a),sn=sin(a);float k=.3333333,q=.5773503;
 float m0=cs+(1.-cs)*k,m1=k*(1.-cs)-q*sn,m2=k*(1.-cs)+q*sn;
 return max(vec3(c.x*m0+c.y*m1+c.z*m2,c.x*m2+c.y*m0+c.z*m1,c.x*m1+c.y*m2+c.z*m0),0.);}
vec3 satc(vec3 c,float s){return max(mix(vec3(dot(c,vec3(.3,.55,.15))),c,s),0.);}
vec3 starc(float k){vec3 b=vec3(.62,.76,1.),w=vec3(1.,.97,.92),o=vec3(1.,.72,.45);
 return k<.45?mix(b,w,k/.45):mix(w,o,(k-.45)/.55);}
float fb3(vec2 p){float a=.5,s=0.;for(int i=0;i<3;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.143;}
float fb4(vec2 p){float a=.5,s=0.;for(int i=0;i<4;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.067;}
vec3 starLayer(vec2 p,float t,float rate,float f0,float prob,float bmin,float bamp,float bpow,float sz,float seed,float px,float spikeAt){
 float tt=t*rate;float N=floor(tt);float fz=tt-N;vec3 acc=vec3(0);
 for(int m=0;m<2;m++){
  float fm=float(m);float e=fm-fz;float A=fm+N;float f=f0*exp2(e);
  float al=m==0?1.-fz:fz;al=al*al*(3.-2.*al);
  vec2 q=p*f+vec2(A*13.1+seed,A*7.7-seed*.5)+S;vec2 ci=floor(q);
  for(int j=0;j<9;j++){
   vec2 g=ci+vec2(float(j%3-1),float(j/3-1));
   if(h21(g+A*3.1+seed)>prob)continue;
   vec2 of=(h22(g+A*1.7+seed)-.5)*.7+.5;vec2 dd=(q-g-of)/f;
   float u=h21(g+9.3+A+seed);float b=bmin+bamp*pow(u,bpow);
   float sg=(1.25+.9*sqrt(b)*sz)*px;
   float rr=dot(dd,dd);float core=exp(-rr/(sg*sg));
   float rd=sqrt(rr);float cf=smoothstep(.9,.35,rd*f);
   float hr=(3.+9.*b*sz)*px;float halo=exp(-rd/hr)*.06*b*cf;
   float spk=0.;
   if(b>spikeAt){float L=(9.+26.*b)*px*sz;spk=(exp(-abs(dd.x)/(.9*px))*exp(-abs(dd.y)/L)+exp(-abs(dd.y)/(.9*px))*exp(-abs(dd.x)/L))*.2*(b-spikeAt)*cf;}
   float tw=h21(g+4.1+seed);
   acc+=starc(tw)*(core*b+halo+spk)*al;
  }
 }
 return acc;}
// Galaxies: two size classes (large, and many small ones), each cell may hold a spiral (two or three arms, varied pitch),
// a barred or plain elliptical, or an edge-on disc; hue from blue-white arms to a yellow core.
vec3 galaxyLayer(vec2 p,float t,float f0,float prob,float rate,float scl,float seed){
 float tt=t*rate;float N=floor(tt);float fz=tt-N;vec3 acc=vec3(0);
 for(int m=0;m<2;m++){
  float fm=float(m);float e=fm-fz;float A=fm+N;float f=f0*exp2(e);
  float al=m==0?1.-fz:fz;al=al*al*(3.-2.*al);
  vec2 q=p*f+vec2(A*5.3,A*9.1)+S+31.+seed;vec2 id=floor(q);vec2 fr=fract(q)-.5;
  if(h21(id+A*2.1+3.+seed)<prob){
   float ty=h21(id+11.+seed);
   vec2 of=(h22(id+A+5.+seed)-.5)*.3;float Rg=(.17+.2*h21(id+2.+seed))*scl;float inc=.3+.65*h21(id+6.+seed);
   vec2 gq=rot(h21(id+8.+seed)*6.28)*(fr-of)/Rg;gq.y/=inc;float gr=length(gq);float th=atan(gq.y,gq.x);
   float arms=ty<.6?.6+.4*cos((2.+floor(h21(id+14.)*2.))*(th-(1.8+2.*h21(id+15.))*log(gr+.1))):1.;
   float disk=ty<.6?exp(-gr*2.6)*arms*.55:(ty<.85?exp(-gr*gr*5.):exp(-abs(gq.y)*7.)*exp(-abs(gq.x)*1.8)*1.4);
   float gi=(disk+exp(-gr*gr*28.)*1.1)*smoothstep(1.2,.8,gr);
   acc+=mix(vec3(.55,.7,1.),vec3(1.,.8,.58),exp(-gr*gr*10.)+ (ty>.6&&ty<.85?.5:0.))*gi*al*.75;}
 }
 return acc;}
vec3 galaxy(vec2 p,float t){return galaxyLayer(p,t,4.,.085,.012,1.,0.)+galaxyLayer(p,t,9.,.2,.017,.55,41.)*.8;}
float rmf(vec2 p){float s=0.,a=.5,w=1.;for(int i=0;i<5;i++){float n=1.-abs(2.*vn(p)-1.);n*=n;s+=n*a*w;w=clamp(n*2.2,.3,1.);p=mat2(1.7,1.3,-1.3,1.7)*p;a*=.62;}return s;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 p=rot(t*.0035)*p;float px=1.2/uRes.y;
 float tt=t*.04;float N=floor(tt);float fz=tt-N;
 // colour regions live in screen space (shared by all layers): emission hue, reflection hue, which of the two
 vec2 cp=p*2.3+S+vec2(t*.003,-t*.002);
 float selE=smoothstep(.3,.7,fb3(cp+4.)),selR=smoothstep(.3,.7,fb3(cp*1.2-6.)),sel=smoothstep(.42,.58,fb3(cp*.7+17.));
 vec3 cE=mix(satc(uC,1.6),satc(hrot(uC,.95),1.6),selE),cR=mix(satc(uA,1.5),satc(hrot(uA,-.8),1.4),selR);
 vec3 gas=vec3(0);float dust=0.,W=0.,dens=0.;
 for(int k=0;k<3;k++){
  float fk=float(k);float e=fk-fz;float A=fk+N;float f=.8*exp2(e*1.25);
  float x=clamp((e+1.)/3.,0.,1.);float wh=.5-.5*cos(6.2832*x);
  vec2 q=rot(A*.9)*p*f+vec2(A*13.7,A*4.1)+S;
  vec2 wv=vec2(fb3(q*.7+3.),fb3(q*.7+11.))-.5;
  float lo=fb3(q*.2+A*3.7);                                   // large-scale: where nebulae live at all
  float n=fb4(q+1.15*wv)+.7*(lo-.5);                          // body field
  float body=smoothstep(.6,.8,n);
  float R=rmf(q*3.1+2.2*wv+A*1.3)*.95;                             // ridged multifractal: filamentary texture inside the body
  float hot=smoothstep(.66,.86,n);
  float fl=pow(1.-abs(2.*fb3(q*1.4+2.2*wv+9.)-1.),12.)*smoothstep(.55,.72,n); // thin shock filaments
  float d=fb4(q*vec2(1.,1.6)+1.5*wv+5.);                      // dust
  float dst=smoothstep(.535,.565,d+.14*body)*(.7+.3*fb3(q*2.7+A));
  float rim=exp(-pow((d+.14*body-.515)/.035,2.))*(1.-dst)*smoothstep(.5,.7,n);
  float Ee=body*(.1+2.6*R*R)+fl*1.3+rim*1.4;
  vec3 gE=cE*Ee+mix(cE,vec3(1.,.92,.82),.6)*hot*hot*(.5+R)*3.;
  vec3 gR=cR*(body*(.12+1.1*R*R)+rim*.7+fl*.35)+cR*hot*.3;
  vec3 g=mix(gR,gE,sel)*(1.-.95*dst);
  gas+=wh*g;dust+=wh*dst;dens+=wh*body;W+=wh;
 }
 W=max(W,1e-3);gas/=W;dust/=W;dens/=W;
 vec3 sFar=starLayer(p,t,.02,17.,.34,.07,.8,3.,.8,0.,px,9.)+starLayer(p,t,.034,10.,.27,.12,1.3,2.6,1.,29.,px,9.);
 vec3 sMid=starLayer(p,t,.06,5.5,.19,.22,1.8,2.4,1.1,53.,px,.9);
 vec3 sNear=starLayer(p,t,.1,3.,.14,.4,2.2,2.,1.2,83.,px,.7);
 vec3 st=sFar*(1.-.9*dust)+sMid*(1.-.6*dust)+sNear;
 emi=gas*.95+st*1.05+galaxy(p,t);
 alb=vec3(.02,.025,.04)+gas*.02;den=.6+dens*1.6+dust*3.5;h=dens*.15+dust*.08;
}
