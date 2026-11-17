import {api} from './client.js';
export const datasets={list:()=>api('/datasets'),get:id=>api('/datasets/'+id),create:data=>api('/datasets',{method:'POST',body:JSON.stringify(data)})};
export const jobs={list:()=>api('/jobs'),get:id=>api('/jobs/'+id),create:data=>api('/jobs',{method:'POST',body:JSON.stringify(data)}),approve:id=>api('/jobs/'+id+'/approve',{method:'POST'})};
export const reports={list:()=>api('/reports'),create:data=>api('/reports',{method:'POST',body:JSON.stringify(data)}),toggle:id=>api('/reports/'+id+'/toggle',{method:'POST'}),deliveries:()=>api('/deliveries')};
export const keyRotation={
 status:()=>api('/key-rotation/status'),
 start:()=>api('/key-rotation/start',{method:'POST'}),
 get:id=>api('/key-rotation/'+id),
 failures:id=>api('/key-rotation/'+id+'/failures'),
 retry:id=>api('/key-rotation/'+id+'/retry',{method:'POST'})
};
