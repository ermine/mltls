open Ocamlbuild_plugin
open Myocamlbuild_config

let _ =  dispatch begin function
  | After_rules ->
      make_binding ~headers:["wrapper.h"] ~lib:"-lssl" "mltls";

      install_lib "mltls" ["libmltls.a"; "dllmltls.so"]
  | _ ->
      ()
end
