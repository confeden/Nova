// Maze: a vast labyrinth of rough stone seen from far above at a tilt, walking forward and leaning over it.
// The world is a grid of fine cells: even/even cells are junction floors, the cells between them are LINKS that are open
// (floor) or closed (wall), the odd/odd cells are pillars. Walls are natural rock: a rounded, slightly irregular edge,
// a height that wanders from block to block, stone tone and veins; corridors are dark gravel. The maze is static (owner:
// the rebuild never looked smooth, so it was removed). Souls -- coloured lights -- walk the corridors; each glows on the floor and
// sends a stream of light upwards, strongest at the floor and thinning out above it. A soul walks the maze as it was when its
// walk began, it leaves no trail. When it fades it is born again elsewhere in a new colour. Far away the surface is
// not marched at all: it is shaded from an anti-aliased distance field, so distant stone is smooth, not pixelated.
uint mz_pcg(uint v){uint s=v*747796405u+2891336453u;uint w=((s>>((s>>28u)+4u))^s)*277803737u;return (w>>22u)^w;}
float mz_h(vec2 id,float k){uint a=uint(int(floor(id.x)));uint b=uint(int(floor(id.y)));
 uint h=mz_pcg(a*1597334677u^mz_pcg(b*3812015801u+uint(int(k*97.))*2654435761u+17u));return float(h&16777215u)/16777216.;}
float mz_bit(vec2 id,float n){return step(mz_h(id+S*.001,n*7.+31.),.6);}
// openness of a fine cell: 1 junction, 0 pillar, links 0..1 (0 = closed wall, 1 = open floor), changing smoothly
float mz_o(vec2 cell,float t){
 float par=mod(cell.x,2.)+2.*mod(cell.y,2.);
 if(par<.5)return 1.;if(par>2.5)return 0.;
 float h0=mz_h(cell,90.);return mz_bit(cell,0.);}                                          // the maze no longer rebuilds: every link keeps its state
// discrete state at one instant (walkers use it): two hashes instead of four
float mz_od(vec2 cell,float t){
 float par=mod(cell.x,2.)+2.*mod(cell.y,2.);
 if(par<.5)return 1.;if(par>2.5)return 0.;
 float h0=mz_h(cell,90.);return mz_bit(cell,0.);}
#define MZ_YH(t) (.95+.1*sin((t)*.037+uSeed))
#define MZ_SC(t) (28.*(1.+.05*sin((t)*.023)))
vec2 mz_map(vec2 p,float t){
 float z=1./(MZ_YH(t)-p.y);float a=.14*sin(t*.019+uSeed*.7);
 vec2 g=rot(a)*(vec2(p.x*z,z)*MZ_SC(t));return g+vec2(1.8*sin(t*.027+uSeed),.6*t)+S*.02;}
vec2 mz_inv(vec2 g,float t){
 float a=.14*sin(t*.019+uSeed*.7);vec2 gp=rot(-a)*(g-vec2(1.8*sin(t*.027+uSeed),.6*t)-S*.02)/MZ_SC(t);
 float z=max(gp.y,.05);return vec2(gp.x/z,MZ_YH(t)-1./z);}
float mz_smin(float a,float b,float k){float h=max(k-abs(a-b),0.)/k;return min(a,b)-h*h*k*.25;}
// signed distance to the floor (negative inside corridors) and the rise of the nearest floor cell
float mz_sd(vec2 fq,float t,out float lift){
 fq+=.1*vec2(vn(fq*2.1)-.5,vn(fq*2.1+9.)-.5);                      // rock is never ruler-straight
 vec2 ci=floor(fq);float sd=9.;float lw=0.,ls=0.;
 for(int j=0;j<9;j++){vec2 cell=ci+vec2(float(j%3-1),float(j/3-1));float o=mz_o(cell,t);if(o<.003)continue;
  float par=mod(cell.x,2.)+2.*mod(cell.y,2.);                      // junctions are squarish pits, links narrower channels that run into them
  vec2 hb=par<.5?vec2(.4):(par<1.5?vec2(.74,.3):vec2(.3,.74));   // a link reaches well into its junctions: a gap between the boxes (.56 vs .6) drew a dark seam across every corridor cell = the tile grid
  vec2 q=abs(fq-(cell+.5))-hb;float d=length(max(q,0.))+min(max(q.x,q.y),0.);
  if(d<.5){float w=exp(-max(d,-.4)*9.);lw+=w;ls+=w*(1.-o);}      // the rise blends over the cell borders: no cliff inside a corridor
  sd=mz_smin(sd,d,.2);}
 lift=lw>0.?ls/lw:1.;
 return sd;}
#define MZ_HMAX 3.5
float mz_height(vec2 fq,float t,out float sd,out float lift){
 sd=mz_sd(fq,t,lift);
 float hw=3.*(1.+.2*(vn(fq*.33)-.5)+.1*(vn(fq*1.3+3.)-.5))+.2*vn(fq*6.);     // wall top wanders from block to block, rough
 return mix(lift*hw,hw,smoothstep(-.04,.17,sd));}
void mz_dir(int d,out vec2 v){v=d==0?vec2(1.,0.):d==1?vec2(0.,1.):d==2?vec2(-1.,0.):vec2(0.,-1.);}
void mz_soul(float t,float si,out vec2 Ps,out vec3 col,out float env){
 float dt=.8+.5*mz_h(vec2(si,1.),3.);float M=8.;float off=mz_h(vec2(si,2.),5.)*M*5.;
 float u=t/dt+off;float ep=floor(u/M);float k=u-ep*M;float n=floor(k);float fr=k-n;
 float te=t-k*dt;                                                   // the maze as it was when this walk began
 // a light that goes out is born again somewhere else in the picture: the start is a random SCREEN point, mapped to the maze at the walk's start
 vec2 sp=vec2(-.62+1.24*mz_h(vec2(si,ep),7.),-.4+.75*mz_h(vec2(si,ep),8.));
 vec2 c=floor(mz_map(sp,te));c=2.*floor(c*.5);
 int pd=-1;vec2 Cb=c+.5;
 for(int i=0;i<10;i++){
  float fl[4];vec2 dv;
  for(int d=0;d<4;d++){mz_dir(d,dv);fl[d]=mz_od(c+dv,te);}
  int rv=pd<0?-1:(pd+2)%4;float cnt=0.;
  for(int d=0;d<4;d++)cnt+=fl[d]*(d==rv?0.:1.);
  int nd=-1;
  if(cnt>.5){float pick=floor(mz_h(c+vec2(si*13.+ep*7.,float(i)),11.)*cnt);float acc=0.;
   for(int d=0;d<4;d++){if(fl[d]>.5&&d!=rv){if(acc==pick){nd=d;}acc+=1.;}}}
  else if(rv>=0&&fl[rv]>.5)nd=rv;
  dv=vec2(0.);if(nd>=0)mz_dir(nd,dv);
  if(float(i)>=n){Cb=c+2.*dv+.5;break;}
  c+=2.*dv;pd=nd<0?pd:nd;}
 vec2 Ca=c+.5;Ps=mix(Ca,Cb,smoothstep(0.,1.,fr));
 env=smoothstep(0.,2.2,k)*smoothstep(M,M-2.2,k);
 // consecutive lights of a slot differ in hue by at least ~a quarter of the circle
 float hs=fract(si*.27+ep*.382+(mz_h(vec2(si,ep),13.)-.5)*.14);col=.5+.5*cos(6.28318*(hs+vec3(0.,.33,.67)));col=mix(col,vec3(1.),.3);col=mix(col,pal(hs),.18);}
vec3 mz_rock(vec2 fq,float shade){
 float tone=.72+.5*vn(fq*2.7)+.25*vn(fq*9.1+4.);
 float vein=smoothstep(.02,0.,abs(vn(fq*3.3+11.)-.5)-.0);
 vec3 base=mix(vec3(.34,.31,.28),vec3(.24,.25,.27),vn(fq*.7+2.));
 base=mix(base,uA*.7,.12*vn(fq*.9+7.));                              // accent shows as lichen in places
 return base*tone*(1.-.35*vein)*shade;}
// the stone/gravel surface seen through one pixel position: colour, height, density and the weights the souls need
void mz_surf(vec2 p,float t,float aaf,float mm,out vec3 alb,out float h,out float den,out vec2 q,out float floorw,out float ah,out float topw,out float facew){
 float zc=1./(MZ_YH(t)-p.y);float sc=MZ_SC(t);
 vec3 floorc=vec3(.035,.04,.052)+uB*.012;
 vec2 q0=mz_map(p,t);
 // cheap path (always): one anti-aliased distance sample; far away it is all there is
 float lf;float sdc=mz_sd(q0,t,lf);float cw=smoothstep(-aaf*1.4,aaf*1.4,sdc);cw=max(cw,smoothstep(.05,.7,lf));
 q=q0;float sd=sdc;ah=cw*3.;topw=cw;floorw=1.-cw;facew=0.;
 if(mm>.001){
  float kvs=.85*.3/(sc*zc);float hit=0.,miss=MZ_HMAX+.01;float Hh=0.;float fh=0.,fm=0.;vec2 qh=q0;float sdh=0.,lfh=0.;
  for(int jj=0;jj<5;jj++){float a=MZ_HMAX*(1.-float(jj)/4.);
   vec2 qj=mz_map(p-vec2(0.,kvs*a),t);float H=mz_height(qj,t,sdh,lfh);
   if(H>=a||jj==4){hit=a;fh=H-a;qh=qj;Hh=H;break;}miss=a;fm=H-a;}
  for(int r=0;r<4;r++){                                             // bisect between the last miss and the hit
   if(miss>MZ_HMAX)break;float a=.5*(hit+miss);vec2 qj=mz_map(p-vec2(0.,kvs*a),t);float sdm,lfm;float H=mz_height(qj,t,sdm,lfm);
   if(H>=a){hit=a;fh=H-a;qh=qj;Hh=H;sdh=sdm;lfh=lfm;}else{miss=a;fm=H-a;}}
  if(miss<=MZ_HMAX)hit=mix(hit,miss,clamp(fh/max(fh-fm,1e-3),0.,1.));   // secant: the depth is continuous, no stair-steps on the faces
  float tw=smoothstep(.1,.2,sdh),fw=1.-smoothstep(-.05,.03,sdh);float vw=max(1.-tw-fw,0.);
  float rs=smoothstep(.05,.7,lfh);                                  // a risen floor is stone, a sunken one gravel: no colour pop when a link opens or closes
  fw*=1.-rs;vw*=1.-rs;tw=1.-fw-vw;
  if(hit<.3){fw=max(fw,.6);tw*=.4;}
  q=mix(q0,qh,mm);sd=mix(sdc,sdh,mm);ah=mix(cw*3.,hit,mm);topw=mix(cw,tw,mm);floorw=mix(1.-cw,fw,mm);facew=mix(0.,vw,mm);}
 // --- stone and gravel
 float shade=.55+.45*smoothstep(0.,MZ_HMAX,ah);
 vec3 top=mz_rock(q,1.);
 vec3 face=mz_rock(vec2(q.x*1.7,ah*3.+q.y*.3),.45*(.6+.4*smoothstep(0.,MZ_HMAX,ah)));
 float ao=mix(.3,1.,smoothstep(0.,.13,-sd));          // saturates near the wall: deeper inside the floor is even (the box overlaps of junctions and links read as a tile grid)
 vec3 flo=floorc*ao*(.8+.4*vn(q*7.));
 alb=top*topw+face*facew+flo*floorw;
 float far=smoothstep(.1,.5,aaf);alb=mix(alb,mix(floorc,top,.55)*.8,far*.5);       // very far: settle towards the average tone
 h=.04+.26*smoothstep(0.,MZ_HMAX,ah)+.03*vn(q*8.);
 den=mix(1.2,45.,clamp(topw+facew,0.,1.));
}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float zc=1./(MZ_YH(t)-p.y);float sc=MZ_SC(t);
 float aaf=(1./uRes.y)*sc*zc*zc*1.3;                                // fine cells per pixel
 float mm=1.-smoothstep(.2,.34,aaf);                                // 1 near: march the heightfield for real walls
 vec2 q;float floorw,ah,topw,facew;
 mz_surf(p,t,aaf,mm,alb,h,den,q,floorw,ah,topw,facew);
 // silhouettes: where the depth or the surface class jumps between neighbouring pixels, average three more taps (anti-aliasing
 // by supersampling only on the edges, so the walls do not crawl in pixels while the maze moves)
 float e1=abs(dFdx(ah))+abs(dFdy(ah));float e2=abs(dFdx(topw))+abs(dFdy(topw))+abs(dFdx(floorw))+abs(dFdy(floorw));
 if(mm>.001&&(e1>.35||e2>.12)){
  float px=1./uRes.y;
  for(int k=0;k<3;k++){
   vec2 o=k==0?vec2(0.,.4):(k==1?vec2(.35,-.2):vec2(-.35,-.2));
   vec3 ak;float hk,dk,ahk,tk,fk,vk;vec2 qk;
   mz_surf(p+o*px,t,aaf,mm,ak,hk,dk,qk,fk,ahk,tk,vk);
   alb+=ak;h+=hk;den+=dk;topw+=tk;floorw+=fk;facew+=vk;}
  alb*=.25;h*=.25;den*=.25;topw*=.25;floorw*=.25;facew*=.25;}
 emi=vec3(.012)*uA*topw;
 // --- souls
 vec3 souls=vec3(0.);float onfloor=floorw;
 for(int s=0;s<4;s++){
  vec2 Ps;vec3 col;float env;mz_soul(t,float(s),Ps,col,env);
  if(env<.01)continue;
  vec2 dq=q-Ps;float d2=dot(dq,dq);
  float pool=exp(-d2/.12)*3.2+exp(-sqrt(d2)/1.1)*.7;
  souls+=col*pool*env*(.12+.88*onfloor)*(1.-.6*smoothstep(.05,.2,aaf));
  // a stream of light rising from the lamp: ribbons that curl upward, dense and bright at the floor, thin and faint above
  vec2 S2=mz_inv(Ps,t);float zS=1./(MZ_YH(t)-S2.y);float ks=1./(zS*.95);
  vec2 dp=p-S2;float Hb=.3*ks;
  if(dp.y>-.004*ks&&dp.y<Hb*2.6){
   float dy=max(dp.y,0.);float w=(.011+.02*dy/Hb)*ks+.002;
   float curl=1.5*sin(dy*5./Hb-t*1.1+float(s)*2.)+.8*sin(dy*11./Hb-t*1.9+float(s));
   float n1=vn(vec2(dp.x/(w*1.3)+curl,dy*3.5/Hb-t*1.7+float(s)*7.));
   float n2=vn(vec2(dp.x/(w*.6)-curl*.7+5.,dy*6./Hb-t*2.6+float(s)*3.));
   float rib=smoothstep(.28,.8,n1)*.8+smoothstep(.5,.85,n2)*.55;
   float prof=exp(-pow(dp.x/w,2.)*.5)*exp(-dy/(.38*Hb))*(.25+1.1*rib);
   float bloom=exp(-dy/(.1*Hb))*exp(-pow(dp.x/(w*1.8),2.)*.5);
   souls+=col*(prof*1.5+bloom*1.4)*env*smoothstep(-.004*ks,.01*ks,dp.y);}}
 emi+=souls;}
