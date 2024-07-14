package com.pnegrete.ForoHub.domain.topico;

import java.time.LocalDateTime;

public record DatosRespuestaTopico(Long id,
                                   String titulo,
                                   String mensaje,
                                   Curso curso,
                                   LocalDateTime fechaCreacion,
                                   Boolean status,
                                   String autor) {
    public DatosRespuestaTopico(Topico topico) {
        this(topico.getId(), topico.getTitulo(), topico.getMensaje(), topico.getCurso(), topico.getFechaCreacion(), topico.getStatus(), topico.getAutor());
    }
}
