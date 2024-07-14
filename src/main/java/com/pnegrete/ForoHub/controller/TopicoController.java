package com.pnegrete.ForoHub.controller;

import com.pnegrete.ForoHub.domain.topico.*;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequestMapping("/topicos")
public class TopicoController {

    @Autowired
    private TopicoRepository topicoRepository;

    @PostMapping
    @Transactional
    public ResponseEntity<DatosRespuestaTopico> crearTopico(@RequestBody @Valid DatosCrearTopico datosCrearTopico,
                                                            UriComponentsBuilder uriComponentsBuilder) {
        Topico topico = new Topico(datosCrearTopico);
        topicoRepository.save(topico);

        DatosRespuestaTopico respuestaTopico = new DatosRespuestaTopico(topico);
        URI url = uriComponentsBuilder.path("/topicos/{id}").buildAndExpand(topico.getId()).toUri();
        return ResponseEntity.created(url).body(respuestaTopico);
    }

    @GetMapping
    public ResponseEntity<Page<DatosListadoTopico>> listadoTopicos(
            @PageableDefault(size = 10, sort = "fechaCreacion", direction = Sort.Direction.ASC) Pageable paginacion,
            @RequestParam(required = false) String curso,
            @RequestParam(required = false) Integer year) {

        Page<Topico> topicos;
        if (curso != null && year != null) {
            LocalDateTime startOfYear = LocalDateTime.of(year, 1, 1, 0, 0);
            LocalDateTime endOfYear = startOfYear.plusYears(1).minusNanos(1);
            topicos = topicoRepository.findByCursoAndFechaCreacionBetween(Curso.valueOf(curso), startOfYear, endOfYear, paginacion);
        } else if (curso != null) {
            topicos = topicoRepository.findByCurso(Curso.valueOf(curso), paginacion);
        } else if (year != null) {
            LocalDateTime startOfYear = LocalDateTime.of(year, 1, 1, 0, 0);
            LocalDateTime endOfYear = startOfYear.plusYears(1).minusNanos(1);
            topicos = topicoRepository.findByFechaCreacionBetween(startOfYear, endOfYear, paginacion);
        } else {
            topicos = topicoRepository.findByStatusTrue(paginacion);
        }
        Page<DatosListadoTopico> result = topicos.map(DatosListadoTopico::new);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}")
    public ResponseEntity<DatosListadoTopico> obtenerTopicoPorId(@PathVariable Long id) {
        Optional<Topico> optionalTopico = topicoRepository.findByIdAndStatusTrue(id);
        return optionalTopico.map(topico -> ResponseEntity.ok(new DatosListadoTopico(topico)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    @Transactional
    public ResponseEntity<DatosRespuestaTopico> actualizarTopico(@PathVariable Long id, @RequestBody @Valid DatosActualizarTopico datosActualizarTopico) {
        Optional<Topico> optionalTopico = topicoRepository.findById(id);
        if (optionalTopico.isPresent()) {
            Topico topico = optionalTopico.get();
            topico.actualizarTopico(datosActualizarTopico);

            topicoRepository.save(topico);

            DatosRespuestaTopico respuestaTopico = new DatosRespuestaTopico(topico);
            return ResponseEntity.ok(respuestaTopico);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    @Transactional
    public ResponseEntity<Void> eliminarTopico(@PathVariable long id) {
        Optional<Topico> optionalTopico = topicoRepository.findById(id);
        if (optionalTopico.isPresent()) {
            Topico topico = optionalTopico.get();
            topico.desactivarTopico();
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
