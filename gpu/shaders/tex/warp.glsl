// WARP: flight at faster-than-light speed. Stars are real points in space (transverse position rho, depth z) and the
// camera plunges down the z axis: a star at depth z is drawn at radius rho/z, and the exposure smears it over the depth
// it covered meanwhile, so it becomes a RADIAL STREAK from rho/(z+dz) to rho/z. Far stars are small dots clustered around
// the vanishing point; as one approaches, its streak grows like 1/z^2, brightens, widens and flies off the edge, with a
// bluish head and a tail that takes the accent colour. Angular bins keep every pixel's search to 3 bins x a few stars.
// Star identity = (layer, bin, slot, cycle), so nothing ever restarts. Faint radial striations hint at the tunnel.
vec3 wp_col(float k,float u){vec3 b=vec3(.62,.78,1.),w=vec3(1.,.96,.9),o=vec3(1.,.74,.5);
 vec3 s=k<.55?mix(b,w,k/.55):mix(w,o,(k-.55)/.45);return mix(mix(uA*1.3,vec3(.5,.7,1.),.5),s,smoothstep(.0,.8,u));}
vec3 wp_layer(vec2 p,float t,float L,float M,int ns,float v,float rho0,float rho1,float bri,float dz,float wpx){
 float rp=length(p);float th=atan(p.y,p.x)/6.2831853+.5;float b0=floor(th*M);vec3 acc=vec3(0.);
 float px=1./uRes.y;
 for(int db=-1;db<=1;db++){float b=b0+float(db);float bm=mod(b,M);
  for(int j=0;j<4;j++){if(j>=ns)break;
   vec2 key=vec2(bm+L*211.,float(j)+L*17.);
   float s=h21(key)+t*v*(.75+.5*h21(key+3.7));float cy=floor(s);float fr=fract(s);
   vec2 k2=key+cy*17.31+uSeed*3.;
   float phi=(b+h21(k2+1.))/M*6.2831853;
   float rho=rho0+(rho1-rho0)*pow(h21(k2+2.),1.4);
   float zend=rho/1.7;float z=mix(1.,zend,fr);          // the star runs on until it is well past the frame edge, then is reborn far away
   float r=rho/z;float ro=rho/(z+dz);
   if(r<rp*.7||ro>rp+.02)continue;                          // the pixel is not between the tail and (just beyond) the head
   float da=th*6.2831853-phi;da=abs(da-6.2831853*floor(da/6.2831853+.5));
   float dperp=rp*da;float w=px*wpx*(1.+2.4*smoothstep(.55,1.,fr));
   if(dperp>w*5.)continue;
   float u=(rp-ro)/max(r-ro,1e-5);
   float tail=pow(clamp(u,0.,1.),1.6);float head=exp(-pow(max(u-1.,0.)*(r-ro)/(w*2.2),2.));
   float prof=exp(-dperp*dperp/(w*w))*(u<1.?tail:head);
   float fade=smoothstep(1.,.78,z);                          // born far away, no pop-in
   float br=(.25+.75*smoothstep(.15,.95,fr))*bri*(.35+1.5*h21(k2+9.)*h21(k2+9.))*fade;
   // a streak of length L carries the energy of the star: shorter streaks are denser, so far stars stay visible points
   float len=(r-ro)/(w*3.);br*=mix(1.4,.55,clamp(len*.12,0.,1.));
   acc+=wp_col(h21(k2+4.),u)*br*prof;}}
 return acc;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 p-=.012*vec2(sin(t*.11+uSeed),sin(t*.083+1.7+uSeed*.7));
 float rp=length(p);float th=atan(p.y,p.x)/6.2831853+.5;
 vec3 st=wp_layer(p,t,0.,170.,3,.16,.02,.55,1.25,.07,1.1);
 st+=wp_layer(p,t,1.,260.,2,.21,.01,.4,.95,.05,.9);
 st+=wp_layer(p,t,2.,110.,2,.12,.04,.9,1.7,.11,1.5);
 st+=wp_layer(p,t,3.,420.,2,.28,.005,.22,.5,.04,.75);
 // tunnel: faint radial striations and a soft haze towards the vanishing point, accent-tinted (no central star)
 float wb=smoothstep(.85,1.,th);float th2=th-1.;   // blend two copies so the striations are periodic in the angle (no seam)
 float n1=mix(vn(vec2(th*90.,rp*3.-t*1.6))*.6+vn(vec2(th*37.+7.,rp*1.5-t*.9))*.4,vn(vec2(th2*90.,rp*3.-t*1.6))*.6+vn(vec2(th2*37.+7.,rp*1.5-t*.9))*.4,wb);
 float stri=smoothstep(.5,.95,n1)*exp(-rp*2.4)*(.4+rp*2.);
 vec3 haze=pal(.55+.3*rp+t*.004)*(stri*.16+exp(-rp*5.5)*.05);
 emi=st+haze;
 den=1.4+.6*clamp(dot(emi,vec3(.33)),0.,2.);
 alb=vec3(.008,.011,.022)+haze*.1;h=0.;}
