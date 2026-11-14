// Sand, close to the ground: desert dunes and heaps of different heights, soft wind-ripples on the windward slopes, a
// low sun that rakes across them (bright windward faces, shaded lee sides, crisp crest lines), and a VERY fine grain
// (one to two pixels) -- no beads, no cells. Endless dive: six scales of the same recipe, Hann-crossfaded.
float fb4(vec2 p){float a=.5,s=0.;for(int i=0;i<4;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.067;}
float fb3(vec2 p){float a=.5,s=0.;for(int i=0;i<3;i++){s+=a*vn(p);p=mat2(1.6,1.2,-1.2,1.6)*p;a*=.5;}return s*1.143;}
float fb2(vec2 p){return (.6*vn(p)+.4*vn(p*2.1+3.7));}
float dune(vec2 q,float A){
 vec2 w=vec2(fb4(q*.30+3.+A),fb4(q*.30+11.+A))-.5;vec2 r=q+2.6*w;           // meandering crests
 float heap=fb4(r*.42+7.+A*2.);float big=fb2(q*.12+19.);                      // mounds of different heights
 float ph=dot(r,vec2(.83,.56))*1.35+3.*(heap-.5);float s=fract(ph);
 float prof=s<.7?pow(smoothstep(0.,.7,s),1.2):1.-smoothstep(.7,1.,s);        // gentle windward rise, steep lee face
 float crest=mix(.35,1.1,smoothstep(.2,.8,big));                              // taller and lower stretches
 float rip=sin(dot(r,vec2(.83,.56))*21.+fb2(r*1.8+5.)*4.5)*.5+.5;             // fine wind ripples, strongest on the windward side
 float rm=smoothstep(.05,.6,s)*(1.-smoothstep(.65,.8,s))*smoothstep(.3,.7,fb2(r*.6+13.));
 return prof*crest*(.55+.6*heap)+.45*heap*big+.034*rip*rm;}
float sH(vec2 p,float t){float tt=t*.075;float N=floor(tt);float fz=tt-N;float H=0.,W=0.;
 for(int k=0;k<4;k++){float fk=float(k);float e=fk-fz;float x=clamp((e+1.)/4.,0.,1.);
  float w=.5-.5*cos(6.2832*x);float f=1.15*exp2(e*1.3);float A=fk+N;
  vec2 q=rot(A*.8)*p*f+S+A*7.3;
  H+=w*dune(q,A)*pow(f,-.85);W+=w;}
 return H/max(W,1e-3);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float e=.0045;vec2 Ld=vec2(-.75,.55);float h0=sH(p,t);float hd=sH(p+Ld*e,t);      // one directional derivative is all the sun needs
 // grain: plain per-pixel noise (two octaves, 1 px and 2 px); no cell grid, so nothing that can be seen to turn or drift
 vec2 px2=floor(p*uRes.y);float n1=h21(px2+S),n2=h21(floor(px2*.5)+17.3);
 vec3 gr=vec3(.45*n1+.55*n2,h21(px2+5.3),step(.992,h21(px2+11.7)));
 float lit=clamp(.8+(hd-h0)/e*.3,.28,1.5);                      // low sun from the left, slightly behind
 float hh=clamp(h0*.9,0.,1.);h=hh+gr.x*.012;
 vec3 deep=mix(vec3(.45,.22,.1),uA*.6,.42),mid=mix(vec3(1.,.69,.28),uA*1.3,.07),high=vec3(1.,.92,.62);        // shadows take the accent hue
 vec3 sandc=mix(deep,mid,smoothstep(.38,.85,lit));sandc=mix(sandc,high,smoothstep(.9,1.35,lit)*.6);
 sandc*=.9+.24*(gr.y-.5);                                                       // grain tone
 sandc=mix(sandc,sandc*.6,gr.z*.8);
 float micro=.88+.3*(gr.x-.35);
 alb=sandc*micro*(.3+.85*lit)*2.3;
 float crest=smoothstep(.95,1.35,lit);
 emi=vec3(1.,.8,.5)*crest*.12+vec3(1.,.9,.7)*gr.z*crest*.15;
 den=8.+hh*10.;}
