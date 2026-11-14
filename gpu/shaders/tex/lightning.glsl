float tri(float x){return abs(fract(x)-.5)*2.-.5;}
float jag(float s,float sd){return .5*(vn(vec2(s*2.3,sd))-.5)+.14*tri(s*5.+sd*3.1+vn(vec2(s*9.,sd)))+.045*tri(s*17.+sd*7.)+.018*tri(s*47.+sd);}
vec2 chp(vec2 P0,vec2 dir,float s,float sd,float amp){vec2 n=vec2(-dir.y,dir.x);return P0+dir*s+n*amp*(jag(s,sd)-jag(0.,sd));}
vec3 chd(vec2 p,vec2 P0,vec2 dir,float sd,float amp){vec2 d=p-P0;float s=dot(d,dir);vec2 n=vec2(-dir.y,dir.x);float q=dot(d,n);
 return vec3(abs(q-amp*(jag(s,sd)-jag(0.,sd))),s,abs(q-amp*.5*(vn(vec2(s*2.3,sd))-vn(vec2(0.,sd)))));}   // .z: the smooth path, for the halos (a halo measured from the jagged path comes out as horizontal streaks)
float chI(float d,float ds,float w){return exp(-d*d/(w*w))+.14*exp(-d*60.);}   // core and hot sheath; the halo is separate (see bolt)
// A bolt is fully described by its seed: origin, heading, reach, jaggedness, number and size of branches, colour,
// strength, how long it takes to grow. While it grows it is only a thin dim line; it flashes and flickers once, at the end,
// when the channel connects (the return stroke), then dies away.
float bolt(vec2 p,float sd,float prog,float lead,float stroke){
 float I=0.;
 float x0=(h21(vec2(sd,1.))-.5)*1.5;
 vec2 P0=vec2(x0,.6+.3*h21(vec2(sd,40.)));
 vec2 dm=normalize(vec2((h21(vec2(sd,2.))-.5)*.9-x0*.25,-1.));
 float Lm=.8+.9*h21(vec2(sd,41.));float amp=.3+.4*h21(vec2(sd,42.));float front=Lm*prog;
 float nb=floor(h21(vec2(sd,43.))*7.99)*step(.2,h21(vec2(sd,44.)));   // 0..7 branches, a fifth of the bolts have none
 float wid=.0022+.0034*h21(vec2(sd,45.));
 vec3 r=chd(p,P0,dm,sd,amp);
 float hd=length(vec2(r.z,max(max(-r.y,r.y-front),0.)));                      // distance to the smooth channel, round ends
 I+=(.11*exp(-hd*14.)+.035*exp(-hd*4.5))*stroke*(.4+.6*prog);
 if(r.y>0.&&r.y<front){float al=.5+1.1*vn(vec2(r.y*28.,sd));I+=chI(r.x,r.z,wid)*(lead*(.55+.4*al)+stroke*al*3.2)*smoothstep(front,front-.05,r.y);}
 for(int b=0;b<7;b++){float fb=float(b);if(fb>=nb)break;float sb=Lm*(.06+.8*h21(vec2(sd,fb+3.)));if(sb>=front)continue;
  float Lb=(.12+.5*h21(vec2(sd,fb+19.)))*(.6+.6*h21(vec2(sd,46.)));float tip=min(Lb,(front-sb)*1.15);
  vec2 P1=chp(P0,dm,sb,sd,amp);if(length(p-P1)>Lb+.06)continue;
  float side=h21(vec2(sd,fb+11.))<.5?-1.:1.;vec2 db=rot(side*(.25+.9*h21(vec2(sd,fb+23.))))*dm;float sd1=sd+fb*7.+1.;
  vec3 r1=chd(p,P1,db,sd1,amp*.8);
  if(r1.y>0.&&r1.y<tip){float ab=.45+1.1*vn(vec2(r1.y*30.,sd1));I+=chI(r1.x,r1.z,wid*.7)*(lead*.8+stroke*ab*1.5)*(1.-.7*r1.y/Lb)*smoothstep(tip,tip-.04,r1.y);}
  float ncb=floor(h21(vec2(sd1,47.))*3.);
  for(int c=0;c<2;c++){float fc=float(c);if(fc>=ncb)break;float sc=Lb*(.25+.5*h21(vec2(sd1,fc+5.)));if(tip<=sc)continue;
   vec2 P2=chp(P1,db,sc,sd1,amp*.8);float sd2=sd1*3.1+fc*5.;float sg=h21(vec2(sd2,2.))<.5?-1.:1.;vec2 d2=rot(sg*(.4+.7*h21(vec2(sd2,4.))))*db;
   float Lc=.06+.2*h21(vec2(sd2,6.));float tp2=min(Lc,(tip-sc)*1.1);
   vec3 r2=chd(p,P2,d2,sd2,amp*.6);
   if(r2.y>0.&&r2.y<tp2)I+=chI(r2.x,r2.z,wid*.5)*(lead*.7+stroke*(.35+.8*vn(vec2(r2.y*35.,sd2))))*(1.-.8*r2.y/Lc)*smoothstep(tp2,tp2-.03,r2.y);}}
 return I;}
vec3 bcol(float sd){float k=h21(vec2(sd,31.));vec3 c=mix(vec3(.62,.76,1.),vec3(1.,.9,.72),smoothstep(.55,.95,k));
 c=mix(c,vec3(.78,.6,1.),smoothstep(.2,.0,abs(k-.3))*.8);c=mix(c,vec3(.45,.95,1.),smoothstep(.12,.0,abs(k-.62))*.8);
 return mix(c,pal(h21(vec2(sd,33.))),.3*h21(vec2(sd,34.)));}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.12;float N=floor(tt);float fz=tt-N;vec3 em=vec3(0);vec3 lit=vec3(0);
 for(int k=0;k<3;k++){float fk=float(k);float e=fk-fz;float A=fk+N;float f=exp2(e*.85);float al=smoothstep(2.,1.2,e)*clamp(e+1.,0.,1.);
  float rate=.3+.45*h21(vec2(A,1.));float u=t*rate+A*.43;float slot=floor(u);float ph=fract(u);
  float sd=mod(slot*7.31+A*13.1,251.);
  float present=step(.3,h21(vec2(sd,3.)));
  float ts=.04+.4*h21(vec2(sd,50.));float gdur=.1+.28*h21(vec2(sd,51.));
  float prog=clamp((ph-ts)/gdur,0.,1.)*step(ts,ph);float hit=step(ts+gdur,ph);float af=(ph-ts-gdur)/max(1.-ts-gdur,.05);
  float fl=sin(af*(40.+30.*h21(vec2(sd,52.))))*exp(-af*3.);
  float stroke=hit*exp(-af*(4.+4.*h21(vec2(sd,53.))))*(1.+1.1*fl);
  float lead=(1.-hit)*.045+hit*.06*exp(-af*3.);
  vec2 pl=p*f;pl.x+=(h21(vec2(sd,7.))-.5)*.2;
  // strength spans a wide range: from a faint far flicker to a blinding strike that lights the whole cloud deck
  float bi=.35+2.6*pow(h21(vec2(sd,9.)),1.7);
  float I=bolt(pl,sd,prog,lead,stroke)*al*bi*present;
  vec3 bc=bcol(sd);
  em+=bc*min(I,3.2)*2.6;
  lit+=bc*stroke*bi*present*al*(.08+.3*h21(vec2(sd,61.)));}                    // the strike lights the clouds from within
 float cl=0.,W=0.;
 for(int k=0;k<5;k++){float fk=float(k);float e=fk-fz;float x=clamp(e/4.,0.,1.);float w=.5-.5*cos(6.2832*x);
  cl+=w*fbm(rot((fk+N)*.7)*p*1.4*exp2(e*.9)+S+(fk+N)*5.3+vec2(t*.01,0.));W+=w;}
 cl/=max(W,1e-3);float cd=smoothstep(.3,.75,cl);
 alb=mix(vec3(.012,.016,.035),vec3(.09,.1,.16),cd);
 emi=em+lit*cd*(.5+.8*cl)*.7;
 den=9.+cd*28.;h=cd*.5;}
