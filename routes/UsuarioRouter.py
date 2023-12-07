from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
    Path,
    Form,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models.Usuario import Usuario
from repositories.UsuarioRepo import UsuarioRepo
from util.seguranca import conferir_senha, obter_hash_senha, obter_usuario_logado
from util.mensagem import redirecionar_com_mensagem  

router = APIRouter(prefix="/usuario")
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def get_index(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    usuarios = UsuarioRepo.obter_todos()

    return templates.TemplateResponse(
        "usuario/index.html",
        {"request": request, "usuario": usuario, "usuarios": usuarios},
    ) 
    
@router.get("/novo")
async def get_novo_usuario(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    return templates.TemplateResponse(
        "usuario/novo.html",
        {"request": request, "usuario": usuario}
    )
    
@router.post("/novo")
async def post_novo_usuario(
    nome: str = Form(...),
    email: str = Form(...), 
    senha: str = Form(...),
    confsenha: str = Form(...),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if senha != confsenha:
        response = redirecionar_com_mensagem("/usuario/novo", "As senhas não coincidem.")
        return response
    
    usuario = Usuario(nome=nome, email=email, senha=obter_hash_senha(senha)) 
    usuario = UsuarioRepo.inserir(usuario)

    response = redirecionar_com_mensagem("/login", "Sua conta foi criada com sucesso! Use seu e-mail e senha para fazer login.")
    return response
    
@router.get("/excluir/{id_usuario:int}", response_class=HTMLResponse)
async def get_excluir(
    request: Request,
    id_usuario: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    usuario_excluir = UsuarioRepo.obter_por_id(id_usuario)

    return templates.TemplateResponse(
        "usuario/excluir.html",
        {"request": request, "usuario": usuario, "usuario_excluir": usuario_excluir},
    )
    
@router.post("/excluir/{id_usuario:int}", response_class=HTMLResponse)
async def post_excluir(
    usuario: Usuario = Depends(obter_usuario_logado),
    id_usuario: int = Path(),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if id_usuario == 1:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível excluir o administrador padrão do sistema.",
        )
        return response

    if id_usuario == usuario.id:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível excluir o próprio usuário que está logado.",
        )
        return response

    UsuarioRepo.excluir(id_usuario)
    response = redirecionar_com_mensagem(
        "/usuario",
        "Usuário excluído com sucesso.",
    )
    return response

@router.get("/alterar/{id_usuario:int}", response_class=HTMLResponse)
async def get_alterar(
    request: Request,
    id_usuario: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    usuario_alterar = UsuarioRepo.obter_por_id(id_usuario)

    return templates.TemplateResponse(
        "usuario/alterar.html",
        {"request": request, "usuario": usuario, "usuario_alterar": usuario_alterar},
    )

@router.post("/alterar/{id_usuario:int}", response_class=HTMLResponse)
async def post_alterar(
    id_usuario: int = Path(),
    nome: str = Form(...),
    email: str = Form(...),
    administrador: bool = Form(False),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if id_usuario == 1:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível alterar dados do administrador padrão.",
        )
        return response

    UsuarioRepo.alterar(
        Usuario(id=id_usuario, nome=nome, email=email, admin=administrador)
    )

    if usuario.admin:
        response = redirecionar_com_mensagem(
            "/usuario/",
            "Usuário alterado com sucesso.",
        )
    else: 
        response = redirecionar_com_mensagem(
            "/usuario/arearestrita",
            "Usuário alterado com sucesso.",
        )

    return response

@router.get("/arearestrita", response_class=HTMLResponse)
async def get_alterar(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    usuario = UsuarioRepo.obter_por_id(usuario.id)

    return templates.TemplateResponse(
        "usuario/arearestrita.html",
        {"request": request, "usuario": usuario}
    )
    
@router.post("/alterarsenha", response_class=HTMLResponse)
async def postAlterarSenha(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
    senhaAtual: str = Form(""),
    novasenha: str = Form(""),
    confnovasenha: str = Form(""),    
):
    hash_senha_bd = UsuarioRepo.obter_senha_por_email(usuario.email)
    if hash_senha_bd:
        if not conferir_senha(senhaAtual, hash_senha_bd):            
            response = redirecionar_com_mensagem("/usuario/arearestrita", "Senha atual incorreta.")
            return response
    
    if novasenha != confnovasenha:
        response = redirecionar_com_mensagem("/usuario/arearestrita", "As senhas não coincidem.")
        return response
    
    # se passou pelas validações, altera a senha no banco de dados
    hash_nova_senha = obter_hash_senha(novasenha)
    UsuarioRepo.alterar_senha(usuario.id, hash_nova_senha)
    
    response = redirecionar_com_mensagem(
            "/usuario/arearestrita",
            "Senha alterada com sucesso.",
        )

    return response 